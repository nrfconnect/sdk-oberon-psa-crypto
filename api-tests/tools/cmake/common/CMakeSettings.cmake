#/** @file
# * Copyright (c) 2019-2020, Arm Limited or its affiliates. All rights reserved.
# * SPDX-License-Identifier : Apache-2.0
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *  http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
#**/

# NOTICE: This file has been modified by Oberon microsystems AG.

if(NOT ${TOOLCHAIN} STREQUAL "INHERIT") # do not override default settings for host OS  /* !!OM */

#Stop built in CMakeDetermine<lang>.cmake scripts to run.
set (CMAKE_C_COMPILER_ID_RUN 1)
#Stop cmake run compiler tests.
set (CMAKE_C_COMPILER_FORCED true)

set(CMAKE_STATIC_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".a")
set(CMAKE_SHARED_LIBRARY_SUFFIX "")

endif()
