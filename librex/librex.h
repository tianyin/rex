#ifndef LIBREX_H
#define LIBREX_H

struct bpf_object;
struct rex_obj;

#ifdef __cplusplus
extern "C" {
#endif

void rex_set_debug(int val);
struct rex_obj *rex_obj_load(const char *file_path);
struct bpf_object *rex_obj_get_bpf(struct rex_obj *obj);

#ifdef __cplusplus
}
#endif

#endif // LIBREX_H
