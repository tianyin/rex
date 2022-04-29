#ifndef LIBIU_H
#define LIBIU_H

#ifdef __cplusplus
extern "C" {
#endif

void iu_set_debug(const int val);
int iu_prog_load(const char *file_path, unsigned prog_type);
int iu_prog_close(int prog_fd);
int iu_prog_get_map(int prog_fd, const char *map_name);
int iu_prog_get_subprog(int prog_fd, const char *subprog_name);
#ifdef __cplusplus
}
#endif

#endif // LIBIU_H
