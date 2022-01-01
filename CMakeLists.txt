FILE(GLOB sources src/*.c)
idf_component_register(SRCS ${sources}
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS "include/pixelflut")
