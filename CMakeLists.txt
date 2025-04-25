# CMAKE version of Fluent-bit
cmake_minimum_required(VERSION 3.12)
project(filter_dnslookup C)

set(CMAKE_C_STANDARD 99)

# Définir le répertoire d'installation de Fluent Bit
set(FLB_DIR "../fluent-bit")

# définir les fichiers sources
set(SRC src/filter_dnslookup.c)

# Inclure les répertoires nécessaires
include_directories(${FLB_DIR}/include ${FLB_DIR}/lib/monkey/include)

# Ajouter le fichier source du plugin
add_library(filter_dnslookup MODULE ${SRC})