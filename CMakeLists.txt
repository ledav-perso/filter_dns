cmake_minimum_required(VERSION 3.10)
project(filter_dnslookup)

set(CMAKE_C_STANDARD 99)

add_subdirectory(../fluent-bit  ../fluent-bit/build)

# Définir le répertoire d'installation de Fluent Bit
set(FLB_DIR "../fluent-bit")

# définir les fichiers sources
set(SRC src/filter_dnslookup.c)

# Inclure les répertoires nécessaires
include_directories(${FLB_DIR}/include)

# Ajouter le fichier source du plugin
add_library(filter_dnslookup SHARED ${SRC})

# Lier Fluent Bit avec le plugin
target_link_libraries(filter_dnslookup ${FLB_DIR}/lib/libfluent-bit.so)