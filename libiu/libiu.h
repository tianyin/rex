#ifndef LIBIU_H
#define LIBIU_H

#ifdef __cplusplus
extern "C" {
#endif

void iu_set_debug(const int val);
int iu_prog_load(const char *file_path);

#ifdef __cplusplus
}
#endif

#endif // LIBIU_H
