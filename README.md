# **1. Project Overview** {#project-overview}

This project simulates the 5G New Radio (5G NR) User Plane Layer 2 protocol stack from the User Equipment (UE) perspective. It models the complete data path --- from raw IP packet generation through the full protocol chain and back --- covering RACH, PDCP, RLC, and MAC layers with HARQ and ARQ error recovery mechanisms.

# **2. Required Source Files** {#required-source-files}

The project consists of seven files. All seven files must reside in the same directory. There are no subdirectories, Makefiles, or CMake files required --- the project compiles with a single command.

| **File**           | **Role**                                            |
| ------------------ | --------------------------------------------------- |
| **main.cpp**       | Entry point --- orchestrates all 6 simulation steps |
| **ip_generator.h** | IP packet and generator classes (Layer 3)           |
| **rach.h**         | 4-message NR RACH procedure with retries            |
| **pdcp.h**         | PDCP layer: ROHC, integrity, ciphering              |
| **rlc.h**          | RLC sender and receiver (AM mode, ARQ, reassembly)  |
| **mac.h**          | MAC sender/receiver and HARQ state machine          |
| **channel.h**      | Uu air interface: 30% loss + MAC grant picker       |
|                    |                                                     |

# **3. Software Environment Requirements** {#software-environment-requirements}

## **3.1 Compiler** {#compiler}

The project requires a C++ compiler supporting at least the C++11 standard. No third-party libraries are used --- only the C++ Standard Library and C Standard Library headers.

## **3.2 Operating System**

The code is fully cross-platform. Instructions are provided below for Linux, macOS, and Windows.

## **3.3 No External Dependencies** {#no-external-dependencies}

The project intentionally uses zero external libraries. Every header used is part of the C++11 standard:

> \<iostream\> --- console output
>
> \<vector\> --- dynamic arrays (IP payloads, RLC PDU lists, etc.)
>
> \<deque\> --- RLC sender queue
>
> \<map\> --- RLC buffers, ROHC context tables
>
> \<cstdint\> --- fixed-width integers (uint8_t, uint16_t, uint32_t)
>
> \<cstdlib\> --- rand(), srand()
>
> \<cstdio\> --- snprintf() for hex formatting
>
> \<string\> --- std::string
>
> \<algorithm\> --- std::min(), std::sort()
>
> \<chrono\> --- high-resolution seed for srand()
>
> \<ctime\> --- time()

# **4. Step-by-Step Setup Instructions** {#step-by-step-setup-instructions}

## **4.1 Linux --- Ubuntu / Debian** {#linux-ubuntu-debian}

### **Step 1: Install GCC**

> sudo apt update

> sudo apt install build-essential \# installs g++, gcc, make

> g++ \--version \# verify: g++ 9.x or later recommended

### **Step 2: Create a Project Directory**

> mkdir \~/5gnr_sim

> cd \~/5gnr_sim

### **Step 3: Place Source Files**

Copy all seven files (main.cpp, channel.h, ip_generator.h, mac.h, pdcp.h, rlc.h, rach.h) into \~/5gnr_sim.

Verify:

> ls \*.cpp \*.

> \# Expected output:

> \#channel.h ip_generator.h mac.h main.cpp pdcp.h rach.h rlc.h

### **Step 4: Compile**

> g++ -std=c++11 -O2 -Wall -Wextra -o sim5g main.cpp

### **Step 5: Run**

> ./sim5g

**4.2 Linux --- Fedora / RHEL / CentOS**

### **Step 1: Install GCC**

> sudo dnf install gcc-c++ \# Fedora / RHEL 8+

> \# OR for older systems:

> sudo yum install gcc-c++

> g++ \--version

Steps 2--5 are identical to section 4.1 above.

**4.3 macOS**

### **Step 1: Install Xcode Command Line Tools**

> xcode-select \--install

> \# Follow the GUI prompt.

> clang++ \--version \# verify: Apple clang version 12+ or Xcode 11+

### **Step 2--3: Create Directory and Place Files**

Same as section 4.1 Steps 2--3.

### **Step 4: Compile**

> clang++ -std=c++11 -O2 -Wall -o sim5g main.cpp

### **Step 5: Run**

> ./sim5g

| **Homebrew GCC:** If you prefer GCC on macOS: brew install gcc, then use g++-13 (or the version installed) instead of clang++. |
| ------------------------------------------------------------------------------------------------------------------------------ |

**4.4 Windows**

### **Option A --- MinGW-w64 (Recommended for Command Line)** {#option-a-mingw-w64-recommended-for-command-line}

1.  Install MinGW-w64 from [[https://winlibs.com]{.underline}](https://winlibs.com) or via MSYS2 (pacman -S mingw-w64-x86_64-gcc).

2.  Add the MinGW bin directory to your PATH environment variable.

3.  Open a Command Prompt or PowerShell and navigate to your project folder.

4.  compile:

> g++ -std=c++11 -O2 -Wall -o sim5g.exe main.cpp
> sim5g.exe

### **Option B (Recommended) --- Visual Studio 2017 or Later** {#option-b-recommended-visual-studio-2017-or-later}

1.  Open Visual Studio and create a new Empty C++ Project.

2.  Add all 7 files to the project (right-click Source Files or Header Files → Add Existing Item).

3.  Set the C++ Language Standard to C++11 or later: Project → Properties → C/C++ → Language → C++ Language Standard.

4.  Build with Ctrl+Shift+B.

5.  Run with Ctrl+F5.

**5. Runtime Behaviour & Configuration**

## **5.1 Environment Variables** {#environment-variables}

This project does not define application-level environment variables. However, one system environment variable must be configured on Windows before the compiler can be used: the PATH variable must include the MinGW bin directory (e.g. C:\mingw64\bin) so that g++ is accessible from the command line. On Linux and macOS the compiler is installed system-wide and no PATH change is needed. All other project configuration is done by editing constants directly in the source files.

| **Info:** The simulation is seeded with std::chrono::high_resolution_clock to ensure different random outcomes on each run --- unlike srand(time(0)) which has only 1-second resolution. |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

**5.2 Configurable Constants**

The following constants can be modified in the source files to adjust simulation behaviour. No recompilation flags are needed --- edit the value and recompile.

| **Constant**           | **File**  | **Defaut** | **Effect**                                                   |
| ---------------------- | --------- | ---------- | ------------------------------------------------------------ |
| **CHANNEL_LOSS_PROB**  | channel.h | 0.30f      | Probability (0--1) of any single air transmission being lost |
| **MAX_ARQ_ROUNDS**     | main.cpp  | 10         | Maximum RLC ARQ recovery rounds before giving up             |
| **maxHARQ(MACSender)** | mac.h     | 4          | Maximum HARQ retransmission attempts per Transport Block     |
| **MAX_RACH_ATTEMPT**   | rach.h    | 5          | Maximum full RACH (Msg1--Msg4) retry cycles                  |
| **packetSize(gen)**    | main.cpp  | 100        | IP payload size in bytes per generated packet                |
| **Packet count (gen)** | main.cpp  | 5          | Number of IP packets to generate and simulate                |
| **xorKey(PDCPLayer)**  | main.cpp  | 0xAB       | XOR ciphering key (NEA2 simulation)                          |

**5.3 MAC Scheduler Grant Distribution**

The simulated gNB scheduler (pickTBGrant() in channel.h) assigns Transport Block sizes using a weighted distribution:

- 25 bytes (25% probability) --- models poor radio conditions / small grant

- 100 bytes (50% probability) --- models typical everyday allocation

- 150 bytes (25% probability) --- models good conditions / large grant

This distribution can be modified in pickTBGrant() in channel.h.
