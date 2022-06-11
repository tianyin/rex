#ifndef LIBIU_H
#define LIBIU_H

#ifdef __cplusplus
extern "C" {
#endif

void iu_set_debug(const int val);
int iu_obj_load(const char *file_path);
int iu_obj_close(int prog_fd);
int iu_obj_get_map(int prog_fd, const char *map_name);
int iu_obj_get_prog(int prog_fd, const char *prog_name);

#ifdef __cplusplus
}
#endif

#endif // LIBIU_H
