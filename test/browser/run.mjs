import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";

const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const dist = path.resolve("test/browser/dist");

const allowed = await runBrowser("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'none'; img-src 'none'");
if (!allowed.includes("<title>PASS</title>")) throw new Error(`Worker/WASM browser test failed.\n${allowed}`);
if (!allowed.includes("omemo2 bidirectional Worker/WASM round trip") || !allowed.includes("legacy bidirectional Worker/WASM round trip")) throw new Error("Both protocol Worker/WASM regressions did not run.");

const blocked = await runBrowser("default-src 'none'; script-src 'self'; worker-src 'self'; connect-src 'self'; style-src 'none'; img-src 'none'");
if (!blocked.includes("<title>FAIL</title>")) throw new Error("CSP without wasm-unsafe-eval unexpectedly allowed the WASM backend.");
if (!/wasm|webassembly/i.test(blocked) || blocked.includes("bidirectional Worker/WASM round trip\",\"ok\":true")) throw new Error("CSP negative test did not specifically prove WASM rejection without fallback.");

console.log("Browser Worker/WASM tests passed; CSP fails closed without 'wasm-unsafe-eval'.");

async function runBrowser(csp) {
	const server = createServer(async (request, response) => {
		try {
			const pathname = new URL(request.url ?? "/", "http://localhost").pathname;
			const relative = pathname === "/" ? "index.html" : pathname.slice(1);
			const file = path.resolve(dist, relative);
			if (!file.startsWith(`${dist}${path.sep}`) && file !== path.join(dist, "index.html")) throw new Error("invalid path");
			const content = await readFile(file);
			response.setHeader("Content-Security-Policy", csp);
			response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
			response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
			response.setHeader("Content-Type", contentType(file));
			response.end(content);
		} catch {
			response.statusCode = 404;
			response.end("not found");
		}
	});

	await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (typeof address !== "object" || address === null) throw new Error("Test server did not bind.");
	const profile = await mkdtemp(path.join(tmpdir(), "picomemo-web-edge-"));

	let result;
	let primaryError;
	try {
		result = await launch(`${address.port}`, profile);
	} catch (error) {
		primaryError = error;
	} finally {
		try {
			await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
			await removeProfile(profile);
		} catch (error) {
			if (!primaryError) primaryError = error;
			else console.error(`Browser cleanup also failed: ${error instanceof Error ? error.message : error}`);
		}
	}
	if (primaryError) throw primaryError;
	return result;
}

async function launch(port, profile) {
	const child = spawn(edge, [
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--remote-debugging-port=0",
		`--user-data-dir=${profile}`,
		`http://127.0.0.1:${port}/`
	], { stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
	let stderr = "";
	let spawnError;
	child.stderr.setEncoding("utf8").on("data", (chunk) => stderr += chunk);
	child.on("error", (error) => spawnError = error);
	let browserSocket;
	let primaryError;
	let result;
	try {
		const endpoint = await readDevToolsEndpoint(profile, () => spawnError);
		browserSocket = new WebSocket(`ws://127.0.0.1:${endpoint.port}${endpoint.browserPath}`);
		await openSocket(browserSocket);
		result = await inspect(endpoint.port);
	} catch (error) {
		primaryError = error;
	} finally {
		try {
			await stopBrowser(child, browserSocket);
		} catch (error) {
			if (!primaryError) primaryError = error;
			else console.error(`Edge shutdown also failed: ${error instanceof Error ? error.message : error}`);
		}
	}
	if (primaryError) throw new Error(`${primaryError instanceof Error ? primaryError.message : primaryError}\n${stderr}`);
	return result;
}

async function readDevToolsEndpoint(profile, getSpawnError) {
	const activePort = path.join(profile, "DevToolsActivePort");
	for (let attempt = 0; attempt < 100; attempt++) {
		const spawnError = getSpawnError();
		if (spawnError) throw spawnError;
		try {
			const [port, browserPath] = (await readFile(activePort, "utf8")).split(/\r?\n/);
			if (port && browserPath) return { port, browserPath };
		} catch {
			await delay(50);
		}
	}
	throw new Error("Edge DevTools endpoint did not start.");
}

async function inspect(port) {
	const targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((response) => response.json());
	const target = targets.find((candidate) => candidate.type === "page");
	if (!target) throw new Error("Edge page target was not found.");
	const socket = new WebSocket(target.webSocketDebuggerUrl);
	await openSocket(socket);

	try {
		for (let attempt = 0; attempt < 300; attempt++) {
			let title;
			try {
				title = await evaluate(socket, attempt + 1, "document.title");
			} catch {
				await delay(100);
				continue;
			}
			if (title === "PASS" || title === "FAIL") {
				const html = await evaluate(socket, attempt + 1000, "document.documentElement.outerHTML");
				return html;
			}
			await delay(100);
		}
		throw new Error("Browser test timed out.");
	} finally {
		socket.close();
	}
}

async function stopBrowser(child, socket) {
	if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ id: 1, method: "Browser.close" }));
	if (await waitForExit(child, 10000)) return;
	child.kill();
	if (!await waitForExit(child, 5000)) throw new Error("Edge did not exit after Browser.close or process termination.");
}

async function waitForExit(child, milliseconds) {
	if (child.exitCode !== null || child.signalCode !== null) return true;
	return Promise.race([
		once(child, "exit").then(() => true),
		delay(milliseconds).then(() => false)
	]);
}

function openSocket(socket) {
	return new Promise((resolve, reject) => {
		socket.onopen = resolve;
		socket.onerror = () => reject(new Error("Could not connect to Edge DevTools."));
	});
}

async function removeProfile(profile) {
	for (let attempt = 0; attempt < 20; attempt++) {
		try {
			await rm(profile, { recursive: true, force: true });
			return;
		} catch (error) {
			if (attempt === 19) throw error;
			await delay(100);
		}
	}
}

function evaluate(socket, id, expression) {
	return new Promise((resolve, reject) => {
		const listener = (event) => {
			const message = JSON.parse(String(event.data));
			if (message.id !== id) return;
			socket.removeEventListener("message", listener);
			if (message.error || message.result?.exceptionDetails) reject(new Error(JSON.stringify(message.error ?? message.result.exceptionDetails)));
			else resolve(message.result.result.value);
		};
		socket.addEventListener("message", listener);
		socket.send(JSON.stringify({ id, method: "Runtime.evaluate", params: { expression, returnByValue: true } }));
	});
}

function delay(milliseconds) {
	return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function contentType(file) {
	switch (path.extname(file)) {
		case ".html": return "text/html; charset=utf-8";
		case ".js":
		case ".mjs": return "text/javascript; charset=utf-8";
		case ".wasm": return "application/wasm";
		default: return "application/octet-stream";
	}
}
