#pragma once

#define BL_CONTAINER_OF(pointer, type, member) \
    ({ __typeof__( ((type *)0)->member ) *__memb = (pointer); \
       (type *)( (char *)__memb - offsetof(type, member) ); })
