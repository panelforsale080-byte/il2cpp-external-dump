#pragma once
#include <cstdint>

typedef int32_t TypeDefinitionIndex;
typedef int32_t GenericParameterIndex;

typedef enum Il2CppTypeEnum {
    IL2CPP_TYPE_END = 0x00,
    IL2CPP_TYPE_VOID = 0x01,
    IL2CPP_TYPE_OBJECT = 0x1c,
    IL2CPP_TYPE_PTR = 0x0f,
    IL2CPP_TYPE_ARRAY = 0x14,
    IL2CPP_TYPE_SZARRAY = 0x1d,
} Il2CppTypeEnum;

struct Il2CppArrayType;
struct Il2CppGenericClass;

struct Il2CppType {
    union {
        void *dummy;
        TypeDefinitionIndex klassIndex;
        const Il2CppType *type;
        Il2CppArrayType *array;
        GenericParameterIndex genericParameterIndex;
        Il2CppGenericClass *generic_class;
    } data;
    unsigned int attrs : 16;
    Il2CppTypeEnum type : 8;
    unsigned int num_mods : 6;
    unsigned int byref : 1;
    unsigned int pinned : 1;
};
