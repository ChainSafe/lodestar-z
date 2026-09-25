// A minimal addon that makes one ArrayBuffer through N-API, as the network bindings create payload buffers, and
// reports the status and any pending exception.
#include <node_api.h>

static napi_value create(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  double size = 0;
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_get_value_double(env, argv[0], &size);
  void *data = NULL;
  napi_value buffer = NULL;
  napi_status status = napi_create_arraybuffer(env, (size_t)size, &data, &buffer);
  bool pending = false;
  napi_is_exception_pending(env, &pending);
  napi_value exception = NULL;
  if (pending) napi_get_and_clear_last_exception(env, &exception);
  napi_value result, value;
  napi_create_object(env, &result);
  napi_create_int32(env, status, &value);
  napi_set_named_property(env, result, "status", value);
  if (exception != NULL) napi_set_named_property(env, result, "exception", exception);
  return result;
}

NAPI_MODULE_INIT() {
  napi_value function;
  napi_create_function(env, "create", NAPI_AUTO_LENGTH, create, NULL, &function);
  napi_set_named_property(env, exports, "create", function);
  return exports;
}
