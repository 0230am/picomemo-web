#include <emscripten.h>
#include <emscripten/heap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "omemo0.h"
#include "omemo2.h"

#define PICOMEMO_WEB_MAX_SKIPPED_KEYS 128
#define PICOMEMO_WEB_SKIPPED_ENTRY_SIZE (4 + 32 + 32)
#define PICOMEMO_WEB_ECAPACITY (-100)
#define PICOMEMO_WEB_EWORKER (-101)
#define PICOMEMO_WEB_ENOMEM (-102)

struct PicomemoWebSkippedState {
  struct omemo2MessageKey keys[PICOMEMO_WEB_MAX_SKIPPED_KEYS];
  uint32_t count;
  uint32_t max_jump;
};

static struct PicomemoWebSkippedState *active_skipped;

struct PicomemoWeb0SkippedState {
  struct omemo0MessageKey keys[PICOMEMO_WEB_MAX_SKIPPED_KEYS];
  uint32_t count;
  uint32_t max_jump;
};

static struct PicomemoWeb0SkippedState *active0_skipped;

EM_JS(int, picomemoWebRandom, (void *p, size_t n), {
  if (typeof document !== "undefined" || !globalThis.crypto ||
      typeof globalThis.crypto.getRandomValues !== "function") return -101;
  const target = HEAPU8.subarray(p, p + n);
  for (let offset = 0; offset < target.length; offset += 65536) {
    globalThis.crypto.getRandomValues(target.subarray(offset, Math.min(offset + 65536, target.length)));
  }
  return 0;
});

static void picomemoWebClear(void *p, size_t n) {
  volatile uint8_t *bytes = p;
  while (n--) *bytes++ = 0;
}

static int picomemoWebLoadMessageKey(struct omemo2Session *session,
                                struct omemo2MessageKey *key) {
  (void)session;
  if (!active_skipped) return OMEMO2_EUSER;
  for (uint32_t i = 0; i < active_skipped->count; i++) {
    struct omemo2MessageKey *candidate = &active_skipped->keys[i];
    if (candidate->nr != key->nr || memcmp(candidate->dh, key->dh, 32)) continue;
    memcpy(key->mk, candidate->mk, 32);
    memmove(candidate, candidate + 1,
            (active_skipped->count - i - 1) * sizeof(*candidate));
    active_skipped->count--;
    return 0;
  }
  return 1;
}

static int picomemoWebStoreMessageKey(struct omemo2Session *session,
                                 const struct omemo2MessageKey *key,
                                 uint64_t fullamount) {
  (void)session;
  if (!active_skipped || fullamount > active_skipped->max_jump)
    return OMEMO2_EUSER;
  if (active_skipped->count >= PICOMEMO_WEB_MAX_SKIPPED_KEYS)
    return OMEMO2_EUSER;
  active_skipped->keys[active_skipped->count++] = *key;
  return 0;
}

static int picomemoWeb0LoadMessageKey(struct omemo0Session *session,
                                 struct omemo0MessageKey *key) {
  (void)session;
  if (!active0_skipped) return OMEMO0_EUSER;
  for (uint32_t i = 0; i < active0_skipped->count; i++) {
    struct omemo0MessageKey *candidate = &active0_skipped->keys[i];
    if (candidate->nr != key->nr || memcmp(candidate->dh, key->dh, 32)) continue;
    memcpy(key->mk, candidate->mk, 32);
    memmove(candidate, candidate + 1,
            (active0_skipped->count - i - 1) * sizeof(*candidate));
    active0_skipped->count--;
    return 0;
  }
  return 1;
}

static int picomemoWeb0StoreMessageKey(struct omemo0Session *session,
                                  const struct omemo0MessageKey *key,
                                  uint64_t fullamount) {
  (void)session;
  if (!active0_skipped || fullamount > active0_skipped->max_jump)
    return OMEMO0_EUSER;
  if (active0_skipped->count >= PICOMEMO_WEB_MAX_SKIPPED_KEYS)
    return OMEMO0_EUSER;
  active0_skipped->keys[active0_skipped->count++] = *key;
  return 0;
}

static int readStore(const uint8_t *p, size_t n, struct omemo2Store *store) {
  memset(store, 0, sizeof(*store));
  return omemo2DeserializeStore(p, n, store);
}

static int readSession(const uint8_t *p, size_t n,
                       struct omemo2Session *session) {
  memset(session, 0, sizeof(*session));
  if (!n) return 0;
  return omemo2DeserializeSession(p, n, session);
}

static int writeStore(const struct omemo2Store *store, uint8_t *out,
                      size_t capacity) {
  size_t n = omemo2GetSerializedStoreSize(store);
  if (n > capacity) return PICOMEMO_WEB_ECAPACITY;
  omemo2SerializeStore(out, store);
  return (int)n;
}

static int writeSession(const struct omemo2Session *session, uint8_t *out,
                        size_t capacity) {
  size_t n = omemo2GetSerializedSessionSize(session);
  if (n > capacity) return PICOMEMO_WEB_ECAPACITY;
  omemo2SerializeSession(out, session);
  return (int)n;
}

static int readStore0(const uint8_t *p, size_t n, struct omemo0Store *store) {
  memset(store, 0, sizeof(*store));
  return omemo0DeserializeStore(p, n, store);
}

static int readSession0(const uint8_t *p, size_t n,
                        struct omemo0Session *session) {
  memset(session, 0, sizeof(*session));
  if (!n) return 0;
  return omemo0DeserializeSession(p, n, session);
}

static int writeStore0(const struct omemo0Store *store, uint8_t *out,
                       size_t capacity) {
  size_t n = omemo0GetSerializedStoreSize(store);
  if (n > capacity) return PICOMEMO_WEB_ECAPACITY;
  omemo0SerializeStore(out, store);
  return (int)n;
}

static int writeSession0(const struct omemo0Session *session, uint8_t *out,
                         size_t capacity) {
  size_t n = omemo0GetSerializedSessionSize(session);
  if (n > capacity) return PICOMEMO_WEB_ECAPACITY;
  omemo0SerializeSession(out, session);
  return (int)n;
}

static int readSkipped(const uint8_t *p, size_t n, uint32_t max_jump,
                       struct PicomemoWebSkippedState *state) {
  memset(state, 0, sizeof(*state));
  state->max_jump = max_jump;
  if (!n) return 0;
  if (n < 4) return OMEMO2_EPROTOBUF;
  uint32_t count = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
                   (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
  if (count > PICOMEMO_WEB_MAX_SKIPPED_KEYS || n != 4 + count * PICOMEMO_WEB_SKIPPED_ENTRY_SIZE)
    return OMEMO2_EPROTOBUF;
  p += 4;
  state->count = count;
  for (uint32_t i = 0; i < count; i++) {
    state->keys[i].nr = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
                        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
    memcpy(state->keys[i].dh, p + 4, 32);
    memcpy(state->keys[i].mk, p + 36, 32);
    p += PICOMEMO_WEB_SKIPPED_ENTRY_SIZE;
  }
  return 0;
}

static int writeSkipped(const struct PicomemoWebSkippedState *state, uint8_t *out,
                        size_t capacity) {
  size_t n = 4 + state->count * PICOMEMO_WEB_SKIPPED_ENTRY_SIZE;
  if (n > capacity) return PICOMEMO_WEB_ECAPACITY;
  out[0] = state->count;
  out[1] = state->count >> 8;
  out[2] = state->count >> 16;
  out[3] = state->count >> 24;
  out += 4;
  for (uint32_t i = 0; i < state->count; i++) {
    const struct omemo2MessageKey *key = &state->keys[i];
    out[0] = key->nr;
    out[1] = key->nr >> 8;
    out[2] = key->nr >> 16;
    out[3] = key->nr >> 24;
    memcpy(out + 4, key->dh, 32);
    memcpy(out + 36, key->mk, 32);
    out += PICOMEMO_WEB_SKIPPED_ENTRY_SIZE;
  }
  return (int)n;
}

static int readSkipped0(const uint8_t *p, size_t n, uint32_t max_jump,
                        struct PicomemoWeb0SkippedState *state) {
  memset(state, 0, sizeof(*state));
  state->max_jump = max_jump;
  if (!n) return 0;
  if (n < 4) return OMEMO0_EPROTOBUF;
  uint32_t count = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
                   (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
  if (count > PICOMEMO_WEB_MAX_SKIPPED_KEYS || n != 4 + count * PICOMEMO_WEB_SKIPPED_ENTRY_SIZE)
    return OMEMO0_EPROTOBUF;
  p += 4;
  state->count = count;
  for (uint32_t i = 0; i < count; i++) {
    state->keys[i].nr = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
                        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
    memcpy(state->keys[i].dh, p + 4, 32);
    memcpy(state->keys[i].mk, p + 36, 32);
    p += PICOMEMO_WEB_SKIPPED_ENTRY_SIZE;
  }
  return 0;
}

static int writeSkipped0(const struct PicomemoWeb0SkippedState *state, uint8_t *out,
                         size_t capacity) {
  size_t n = 4 + state->count * PICOMEMO_WEB_SKIPPED_ENTRY_SIZE;
  if (n > capacity) return PICOMEMO_WEB_ECAPACITY;
  out[0] = state->count;
  out[1] = state->count >> 8;
  out[2] = state->count >> 16;
  out[3] = state->count >> 24;
  out += 4;
  for (uint32_t i = 0; i < state->count; i++) {
    const struct omemo0MessageKey *key = &state->keys[i];
    out[0] = key->nr;
    out[1] = key->nr >> 8;
    out[2] = key->nr >> 16;
    out[3] = key->nr >> 24;
    memcpy(out + 4, key->dh, 32);
    memcpy(out + 36, key->mk, 32);
    out += PICOMEMO_WEB_SKIPPED_ENTRY_SIZE;
  }
  return (int)n;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebSetupStore(uint8_t *out, size_t capacity) {
  struct omemo2Store store;
  memset(&store, 0, sizeof(store));
  int result = omemo2SetupStore(&store);
  if (!result) result = writeStore(&store, out, capacity);
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebGetBundle(
    const uint8_t *serialized, size_t n, uint8_t *identity,
    uint8_t *signed_prekey, uint8_t *signature, uint32_t *metadata,
    uint32_t *prekey_ids, uint8_t *prekeys) {
  struct omemo2Store store;
  int result = readStore(serialized, n, &store);
  if (!result) {
    memcpy(identity, store.identity.pub, 32);
    memcpy(signed_prekey, store.cursignedprekey.kp.pub, 32);
    memcpy(signature, store.cursignedprekey.sig, 64);
    metadata[0] = store.cursignedprekey.id;
    metadata[1] = 0;
    for (int i = 0; i < OMEMO2_NUMPREKEYS; i++) {
      if (!store.prekeys[i].id) continue;
      prekey_ids[metadata[1]] = store.prekeys[i].id;
      memcpy(prekeys + metadata[1] * 32, store.prekeys[i].kp.pub, 32);
      metadata[1]++;
    }
    if (!metadata[1]) result = OMEMO2_EKEYGONE;
  }
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebReplenishStore(
    const uint8_t *serialized, size_t n, uint8_t *out, size_t capacity) {
  struct omemo2Store store;
  int result = readStore(serialized, n, &store);
  if (!result) result = omemo2RefillPreKeys(&store);
  if (!result) result = writeStore(&store, out, capacity);
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebInitiateSession(
    const uint8_t *store_bytes, size_t store_n, const uint8_t *identity,
    const uint8_t *signed_prekey, const uint8_t *signature,
    uint32_t signed_prekey_id, const uint8_t *prekey, uint32_t prekey_id,
    uint8_t *out, size_t capacity) {
  struct omemo2Store store;
  struct omemo2Session session;
  memset(&session, 0, sizeof(session));
  int result = readStore(store_bytes, store_n, &store);
  if (!result) result = omemo2InitiateSession(&session, &store, signature,
      signed_prekey, identity, prekey, signed_prekey_id, prekey_id);
  if (!result) result = writeSession(&session, out, capacity);
  picomemoWebClear(&session, sizeof(session));
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebEncryptKey(
    const uint8_t *session_bytes, size_t session_n, const uint8_t *key,
    size_t key_n, uint8_t *session_out, size_t session_capacity,
    uint8_t *message_out, size_t message_capacity, uint32_t *metadata) {
  struct omemo2Session session;
  struct omemo2KeyMessage message;
  memset(&message, 0, sizeof(message));
  int result = readSession(session_bytes, session_n, &session);
  if (!result) result = omemo2EncryptKey(&session, &message, key, key_n);
  if (!result && message.n > message_capacity) result = PICOMEMO_WEB_ECAPACITY;
  if (!result) {
    int session_n_out = writeSession(&session, session_out, session_capacity);
    if (session_n_out < 0) result = session_n_out;
    else {
      memcpy(message_out, message.p, message.n);
      metadata[0] = session_n_out;
      metadata[1] = message.n;
      metadata[2] = message.isprekey;
    }
  }
  picomemoWebClear(&message, sizeof(message));
  picomemoWebClear(&session, sizeof(session));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebGetSessionIdentity(
    const uint8_t *session_bytes, size_t session_n, uint8_t *identity_out) {
  struct omemo2Session session;
  int result = readSession(session_bytes, session_n, &session);
  if (!result && !session.init) result = OMEMO2_EPROTOBUF;
  if (!result) memcpy(identity_out, session.remoteidentity, 32);
  picomemoWebClear(&session, sizeof(session));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebMaintainSession(
    const uint8_t *store_bytes, size_t store_n,
    const uint8_t *session_bytes, size_t session_n,
    uint8_t *session_out, size_t session_capacity,
    uint8_t *message_out, size_t message_capacity, uint32_t *metadata) {
  struct omemo2Store store;
  struct omemo2Session session;
  struct omemo2KeyMessage message;
  memset(&message, 0, sizeof(message));
  int result = readStore(store_bytes, store_n, &store);
  if (!result) result = readSession(session_bytes, session_n, &session);
  if (!result && !session.init) result = OMEMO2_EPROTOBUF;
  if (!result) result = omemo2Heartbeat(&session, &store, &message);
  if (!result && message.n > message_capacity) result = PICOMEMO_WEB_ECAPACITY;
  if (!result) {
    int session_n_out = writeSession(&session, session_out, session_capacity);
    if (session_n_out < 0) result = session_n_out;
    else {
      memcpy(message_out, message.p, message.n);
      metadata[0] = session_n_out;
      metadata[1] = message.n;
      metadata[2] = message.isprekey;
      metadata[3] = session.state.ns;
      metadata[4] = session.state.nr;
      metadata[5] = session.state.pn;
    }
  }
  picomemoWebClear(&message, sizeof(message));
  picomemoWebClear(&session, sizeof(session));
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebDecryptKey(
    const uint8_t *store_bytes, size_t store_n,
    const uint8_t *session_bytes, size_t session_n,
    const uint8_t *skipped_bytes, size_t skipped_n, uint32_t max_jump,
    int is_prekey, const uint8_t *message, size_t message_n,
    uint8_t *store_out, size_t store_capacity,
    uint8_t *session_out, size_t session_capacity,
    uint8_t *skipped_out, size_t skipped_capacity,
    uint8_t *key_out, size_t key_capacity, uint32_t *metadata) {
  struct omemo2Store store;
  struct omemo2Session session;
  struct PicomemoWebSkippedState skipped;
  size_t key_n = key_capacity;
  int result = readStore(store_bytes, store_n, &store);
  if (!result) result = readSession(session_bytes, session_n, &session);
  if (!result) result = readSkipped(skipped_bytes, skipped_n, max_jump, &skipped);
  if (!result) {
    active_skipped = &skipped;
    result = omemo2DecryptKey(&session, &store, key_out, &key_n,
                              is_prekey, message, message_n);
    active_skipped = NULL;
  }
  if (!result && is_prekey && session.usedpk_id) {
    for (int i = 0; i < OMEMO2_NUMPREKEYS; i++) {
      if (store.prekeys[i].id != session.usedpk_id) continue;
      picomemoWebClear(&store.prekeys[i], sizeof(store.prekeys[i]));
      break;
    }
  }
  if (!result) {
    int store_result = writeStore(&store, store_out, store_capacity);
    int session_result = writeSession(&session, session_out, session_capacity);
    int skipped_result = writeSkipped(&skipped, skipped_out, skipped_capacity);
    if (store_result < 0) result = store_result;
    else if (session_result < 0) result = session_result;
    else if (skipped_result < 0) result = skipped_result;
    else {
      metadata[0] = store_result;
      metadata[1] = session_result;
      metadata[2] = skipped_result;
      metadata[3] = key_n;
    }
  }
  picomemoWebClear(&skipped, sizeof(skipped));
  picomemoWebClear(&session, sizeof(session));
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebEncryptMessage(
    const uint8_t *plaintext, size_t plaintext_n, uint8_t *payload,
    size_t payload_capacity, uint8_t *key) {
  size_t padded_n = plaintext_n + omemo2GetMessagePadSize(plaintext_n);
  if (padded_n > payload_capacity) return PICOMEMO_WEB_ECAPACITY;
  uint8_t *copy = malloc(padded_n);
  if (!copy) return PICOMEMO_WEB_ENOMEM;
  memcpy(copy, plaintext, plaintext_n);
  int result = omemo2EncryptMessage(payload, key, copy, plaintext_n);
  picomemoWebClear(copy, padded_n);
  free(copy);
  return result ? result : (int)padded_n;
}

EMSCRIPTEN_KEEPALIVE int picomemoWebDecryptMessage(
    const uint8_t *key, size_t key_n, const uint8_t *payload,
    size_t payload_n, uint8_t *plaintext, size_t plaintext_capacity) {
  if (payload_n > plaintext_capacity) return PICOMEMO_WEB_ECAPACITY;
  size_t plaintext_n = plaintext_capacity;
  int result = omemo2DecryptMessage(plaintext, &plaintext_n, key, key_n,
                                    payload, payload_n);
  return result ? result : (int)plaintext_n;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0SetupStore(uint8_t *out, size_t capacity) {
  struct omemo0Store store;
  memset(&store, 0, sizeof(store));
  int result = omemo0SetupStore(&store);
  if (!result) result = writeStore0(&store, out, capacity);
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0GetBundle(
    const uint8_t *serialized, size_t n, uint8_t *identity,
    uint8_t *signed_prekey, uint8_t *signature, uint32_t *metadata,
    uint32_t *prekey_ids, uint8_t *prekeys) {
  struct omemo0Store store;
  int result = readStore0(serialized, n, &store);
  if (!result) {
    memcpy(identity, store.identity.pub, 32);
    memcpy(signed_prekey, store.cursignedprekey.kp.pub, 32);
    memcpy(signature, store.cursignedprekey.sig, 64);
    metadata[0] = store.cursignedprekey.id;
    metadata[1] = 0;
    for (int i = 0; i < OMEMO0_NUMPREKEYS; i++) {
      if (!store.prekeys[i].id) continue;
      prekey_ids[metadata[1]] = store.prekeys[i].id;
      memcpy(prekeys + metadata[1] * 32, store.prekeys[i].kp.pub, 32);
      metadata[1]++;
    }
    if (!metadata[1]) result = OMEMO0_EKEYGONE;
  }
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0ReplenishStore(
    const uint8_t *serialized, size_t n, uint8_t *out, size_t capacity) {
  struct omemo0Store store;
  int result = readStore0(serialized, n, &store);
  if (!result) result = omemo0RefillPreKeys(&store);
  if (!result) result = writeStore0(&store, out, capacity);
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0InitiateSession(
    const uint8_t *store_bytes, size_t store_n, const uint8_t *identity,
    const uint8_t *signed_prekey, const uint8_t *signature,
    uint32_t signed_prekey_id, const uint8_t *prekey, uint32_t prekey_id,
    uint8_t *out, size_t capacity) {
  struct omemo0Store store;
  struct omemo0Session session;
  omemo0SerializedKey serialized_identity;
  omemo0SerializedKey serialized_signed_prekey;
  omemo0SerializedKey serialized_prekey;
  memset(&session, 0, sizeof(session));
  serialized_identity[0] = 5;
  serialized_signed_prekey[0] = 5;
  serialized_prekey[0] = 5;
  memcpy(serialized_identity + 1, identity, 32);
  memcpy(serialized_signed_prekey + 1, signed_prekey, 32);
  memcpy(serialized_prekey + 1, prekey, 32);
  int result = readStore0(store_bytes, store_n, &store);
  if (!result) result = omemo0InitiateSession(&session, &store, signature,
      serialized_signed_prekey, serialized_identity, serialized_prekey,
      signed_prekey_id, prekey_id);
  if (!result) result = writeSession0(&session, out, capacity);
  picomemoWebClear(serialized_identity, sizeof(serialized_identity));
  picomemoWebClear(serialized_signed_prekey, sizeof(serialized_signed_prekey));
  picomemoWebClear(serialized_prekey, sizeof(serialized_prekey));
  picomemoWebClear(&session, sizeof(session));
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0EncryptKey(
    const uint8_t *session_bytes, size_t session_n, const uint8_t *key,
    size_t key_n, uint8_t *session_out, size_t session_capacity,
    uint8_t *message_out, size_t message_capacity, uint32_t *metadata) {
  struct omemo0Session session;
  struct omemo0KeyMessage message;
  memset(&message, 0, sizeof(message));
  int result = readSession0(session_bytes, session_n, &session);
  if (!result) result = omemo0EncryptKey(&session, &message, key, key_n);
  if (!result && message.n > message_capacity) result = PICOMEMO_WEB_ECAPACITY;
  if (!result) {
    int session_n_out = writeSession0(&session, session_out, session_capacity);
    if (session_n_out < 0) result = session_n_out;
    else {
      memcpy(message_out, message.p, message.n);
      metadata[0] = session_n_out;
      metadata[1] = message.n;
      metadata[2] = message.isprekey;
    }
  }
  picomemoWebClear(&message, sizeof(message));
  picomemoWebClear(&session, sizeof(session));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0GetSessionIdentity(
    const uint8_t *session_bytes, size_t session_n, uint8_t *identity_out) {
  struct omemo0Session session;
  int result = readSession0(session_bytes, session_n, &session);
  if (!result && !session.init) result = OMEMO0_EPROTOBUF;
  if (!result) memcpy(identity_out, session.remoteidentity, 32);
  picomemoWebClear(&session, sizeof(session));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0DecryptKey(
    const uint8_t *store_bytes, size_t store_n,
    const uint8_t *session_bytes, size_t session_n,
    const uint8_t *skipped_bytes, size_t skipped_n, uint32_t max_jump,
    int is_prekey, const uint8_t *message, size_t message_n,
    uint8_t *store_out, size_t store_capacity,
    uint8_t *session_out, size_t session_capacity,
    uint8_t *skipped_out, size_t skipped_capacity,
    uint8_t *key_out, size_t key_capacity, uint32_t *metadata) {
  struct omemo0Store store;
  struct omemo0Session session;
  struct PicomemoWeb0SkippedState skipped;
  size_t key_n = key_capacity;
  int result = readStore0(store_bytes, store_n, &store);
  if (!result) result = readSession0(session_bytes, session_n, &session);
  if (!result) result = readSkipped0(skipped_bytes, skipped_n, max_jump, &skipped);
  if (!result) {
    active0_skipped = &skipped;
    result = omemo0DecryptKey(&session, &store, key_out, &key_n,
                              is_prekey, message, message_n);
    active0_skipped = NULL;
  }
  if (!result && is_prekey && session.usedpk_id) {
    for (int i = 0; i < OMEMO0_NUMPREKEYS; i++) {
      if (store.prekeys[i].id != session.usedpk_id) continue;
      picomemoWebClear(&store.prekeys[i], sizeof(store.prekeys[i]));
      break;
    }
  }
  if (!result) {
    int store_result = writeStore0(&store, store_out, store_capacity);
    int session_result = writeSession0(&session, session_out, session_capacity);
    int skipped_result = writeSkipped0(&skipped, skipped_out, skipped_capacity);
    if (store_result < 0) result = store_result;
    else if (session_result < 0) result = session_result;
    else if (skipped_result < 0) result = skipped_result;
    else {
      metadata[0] = store_result;
      metadata[1] = session_result;
      metadata[2] = skipped_result;
      metadata[3] = key_n;
    }
  }
  picomemoWebClear(&skipped, sizeof(skipped));
  picomemoWebClear(&session, sizeof(session));
  picomemoWebClear(&store, sizeof(store));
  return result;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0EncryptMessage(
    const uint8_t *plaintext, size_t plaintext_n, uint8_t *payload,
    size_t payload_capacity, uint8_t *key, uint8_t *iv) {
  if (plaintext_n > payload_capacity) return PICOMEMO_WEB_ECAPACITY;
  int result = omemo0EncryptMessage(payload, key, iv, plaintext, plaintext_n);
  return result ? result : (int)plaintext_n;
}

EMSCRIPTEN_KEEPALIVE int picomemoWeb0DecryptMessage(
    const uint8_t *key, size_t key_n, const uint8_t *iv, size_t iv_n,
    const uint8_t *payload, size_t payload_n, uint8_t *plaintext,
    size_t plaintext_capacity) {
  if (payload_n > plaintext_capacity) return PICOMEMO_WEB_ECAPACITY;
  if (iv_n != 12) return OMEMO0_EPARAM;
  int result = omemo0DecryptMessage(plaintext, key, key_n, iv, payload, payload_n);
  return result ? result : (int)payload_n;
}

EMSCRIPTEN_KEEPALIVE void picomemoWebInitialize(void) {
  omemo0SetCallbacks(picomemoWeb0LoadMessageKey, picomemoWeb0StoreMessageKey, picomemoWebRandom);
  omemo2SetCallbacks(picomemoWebLoadMessageKey, picomemoWebStoreMessageKey, picomemoWebRandom);
}

EMSCRIPTEN_KEEPALIVE size_t picomemoWebHeapSize(void) {
  return emscripten_get_heap_size();
}
