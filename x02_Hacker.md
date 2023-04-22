# The Hacker - Level 02

First of all, congrats on getting this far; you can now successfully hack something. You must understand by this time that learning never ends and that you still have to learn more before you can describe yourself as a professional. If you do not comprehend the technologies, processes, vulnerabilities, and security solutions stated in the [[x01_Newbie]]'s path, you should not be in this level.

This is the last section of the road map, and it focuses on the more sophisticated information you need to know to identify yourself as a professional.

## What you should focus on
You have already learnt a lot about web applications, and you can test them successfully for weaknesses and talk to clients about contemporary solutions. Great! It is time to advance your reverse engineering abilities, learn about memory management and low-level computation, as well as mobile application security and strategies to get beyond current OS-Level security measures like DEP, ASLR, and Stack Canaries.

### Mastering the Big 4
-   Network Security
-   Web Application Security
-   Binary Security / Reverse Engineering
-   Mobile Application Security

### Advanced Penetration Testing Tools
-   **Reverse Engineering Tools**
    -   Windows-Based Tools
        -   Flare VM
        -   SysInternals
        -   CFF Explorer
        -   Get-PESecurity
    -   Linux-Based Tools
        -   gdb-peda
            -   checksec
        -   pwndbg
    -   Fuzzers
        -   SPIKE
            -   .spk
            -   generic_send_tcp
            -   generic_send_udp
            -   generic_chunked
        -   PEACH Fuzzer
    -   PwnTools

### Advanced Web Application Exploitation

-   Bypassing WAFs
-   Malicious File Uploads
    -   .pdf Upload Attacks
        -   XSS Embedded PDF Attacks
        -   XXE Embedded PDF Attacks
    -   .doc Upload Attacks
    -   img Upload Attacks
-   XXE-OOB Exploitation

### C/C++ Programming Essentials

-   Variable Types
    -   int
    -   double
    -   float
    -   char
-   stdin & stdout
-   File Descriptors
-   Sockets
-   Signed vs. Unsigned
    -   Twos-Compliment
-   Object-Oriented Programming
    -   Encapsulation
    -   Abstraction
    -   Inheritance
    -   Polymorphism
-   Buffers
    -   Arrays
    -   Strings _(Behavior in memory)_
-   Pointers
    -   Smart Pointers
    -   Linked-Listed
-   Vectors
-   Type Casting
-   References


### Advanced Network-Based Vulnerabilities

-   SSL/TLS Vulnerabilities
    -   POODLE
    -   BEAST
    -   CRIME
    -   FREAK
    -   DROWN
    -   SWEET32
    -   NOMORE
    -   BREACH
    -   HeartBleed

### Reverse Engineering

-   **Binary Fundamentals**
    
    -   Endianness
        -   Big Endian
        -   Little Endian
    -   The Stack
        -   Stack Frames
            -   Function Recursion
            -   LIFO
            -   Variable positions on the stack
            -   Return Address _(RET)_
    -   The Heap
        -   Allocating Memory
        -   Freeing Memory
        -   Garbage Collection
        -   Vtables
    -   CPU Registers
        -   Intruction Pointer _(EIP / RIP)_
        -   Stack Pointer _(ESP / RSP)_
        -   Base Pointer _(EBP / RBP)_
        -   Accumulator Register _(EAX)_
        -   Counter Register _(ECX)_
        -   Data Register _(EDI)_
    -   ELF Binaries
        -   Dynamic Libraries
        -   Global Offset Table _(GOT)_
        -   Procedure Linkage Table _(PLT)_
-   **Modern Binary Protection Techniques**
    
    -   Linux-Based Protections
        -   PaX _(Security Team)_
            -   NOEXEC
            -   mprotect()
            -   RAP
        -   PIE
        -   RELRO
        -   Stack Guard _(Canary Derivative)_
    -   Windows-Based Protections
        -   DEP _(NX-Bit Derivative)_
        -   CFG / RFG
        -   Shadow Stacks
            -   Shadow Stack Pointer _(SSP)_
        -   Isolated Heaps _(MS14-035)_
        -   Microsoft's MemoryProtection _(MS14-037)_
        -   MemGC _(Automated Memory Garabage Collection)_
            -   HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\Main::OverrideMemoryProtectionSetting
        -   CIG _(Code Integrity Guard)_
        -   ACG _(Arbitrary Code Guard)_
    -   OS Independent Protections
        -   W^X
        -   ASLR
        -   Stack Canaries
            -   Random canaries
            -   Random XOR Canaries
            -   Terminator Canaries
        -   CFI _(pax_future.txt)_
            -   Code-Pointer Separation
            -   Code-Pointer Integrity
            -   Vtable Pointer Verification
        -   SafeSEH & SEHOP
            -   Zeroing CPU Registers
-   **Fundamental Exploit Development Techniques** _(Protection Bypasses are in Level 3)_
    
    -   Stack-Based Buffer Overflow
        -   NULL Byte _(0x00)_
        -   Return Pointer Overwrite
        -   NOP Sleds
        -   Off-By-One Error
    -   SEH-Based Buffer Overflow
    -   Heap Exploitation
        -   Use-After-Free
            -   Dangling Pointers
            -   Type Confusion Attacks


### Mobile Fundamentals

-   Mobile Communications
    -   SIM Card
    -   LTE
    -   3G
    -   4G
    -   5G
-   Mobile Data Storage
-   Rooting
-   Jailbreaking
-   APKs

### Mobile Application Security

-   **Mobile OWASP Top 10**
    -   Improper Platform Usage
    -   Insecure Data Storage
    -   Insecure Communication
    -   Insecure Authentication
    -   Insufficient Cryptography
    -   Insecure Authorization
    -   Client Code Quality
    -   Code Tampering
    -   Reverse Engineering
    -   Extraneous Functionality


### Advanced Web Application Security Bypasses

-   Bypassing Modern XSS Protections

## Cloud-Based Penetration Testing

#### Popular Cloud Hacking Tools:
-   dnscat2
-   Cloud Storage Tester

#### Attacks:
-   Stealing AWS Access Keys
    -   SSRF
        -   XXE-OOB
            -   Documents with XXE payload
            -   PDFs with XXE playload
        -   SVG with Embedded links
    -   Exploiting Deserialization Bugs
    -   Command Injection
        -   Uploading filenames with code paramenters
            -   Printing environment variables
    -   Malicious File Upload
        -   ImageTragick

### AWS Cloud Security

#### Protecting AWS Access Keys

-   **Best Practices:**
    -   Removing Root Access Keys
    -   Never hardcode AWS keys into code
        -   _Keys can be leaked via public repositiories like Github._
    -   Avoid storing AWS keys into environment variables
    -   Use IAM Instance Profiles to request resources
        -   Temporary Role Credentials
    -   Enable IMDSv2 Tokens
    -   Never embed keys into mobile apps _(use AWS Cognito)_
-   **Tools:**
    -   aws-vault
        -   Temporary access keys
    -   AWS Secrets Manager
    -   MFA-protected API access _(IAM setting)_
        -   "aws:MultiFactorAuthPresent": "true"
            -   MFA protecting cross-account delegation
            -   MFA protecting instance termination, etc.
            -   MFA protecting resources that have resource-based policies

#### Popular AWS SDKs

-   Boto3 _(Python)_
    -   aws configure
        -   ~/.aws/credentials
    -   boto3.Session()
    -   boto3.resource()
    -   boto3.client()

#### Securing AWS Resources

-   Security Groups
    -   Inbound Rules
    -   Outbound Rules
-   AWS WAF
    -   Checkpoints

#### Securing Communications

-   Confidentality
-   Integrity
    -   AWS SigV4
-   Availability
    -   AWS Shield _(DDoS Protection)_
        -   Standard
        -   Advanced

#### Securing Data-At-Rest

-   Confidentality
    -   AWS KMS
    -   S3 Bucket Permissions
-   Integrity
-   Availabity
    -   S3 Versioning
    -   S3 Object lifecycle Management
        -   Transition Actions
        -   Expiration Actions
        -   LifeCycle Scopes

#### Identity, Authentication, and Authorization

-   AWS IAM
    -   Users
    -   Groups

#### Logging, Monitoring, and Auditing

-   AWS Trusted Advisor
    -   Check-Level Status
        -   Okay-State
        -   Warning-State
        -   Error-State
-   AWS CloudWatch
-   AWS CloudTrail
-   AWS Config
-   AWS Artitfact

### AWS Serverless

-   Serverless Services:
    -   AWS API Gateway
    -   AWS LAMBDA
    -   AWS Fargate
    -   AWS EKS
    -   Kubernetes
-   Other Services
-   AWS Kenisis

## Exploit Development

### Modern Technologies

-   Ahead-Of-Time Compilers _(AOT)_
    -   Lexical Analyzer
        -   Token Streams
    -   Syntax Parser / Analyzer
        -   Abstract Syntax Tree
    -   IR Generator
        -   Intermediate Representation
    -   IR Optimizer
-   Just-In-Time Compilers _(JIT)_
    -   JIT Designs:
        -   Tracing JIT Design
            -   Profiling Phase
            -   Tracing Phase
            -   Optimizating Phase
        -   Method JIT Design
    -   JIT Features:
        -   Profile-Guided Optimization
        -   Pseudo-Constant Propagation
            -   Dead Code Elimination
        -   Indirect-Virtual Function Inlining


### Bypassing Modern Exploitation Prevention

-   Memory Leak Vulnerabilities
    -   printf()
    -   Abusing the Meltdown Exploit
    -   Error message with memory addresses
-   Bypassing NX-Bit
    -   Return-to-LibC
        -   Executing function calls
            -   system()
    -   Return-Oriented Programming _(Gadget Chains)_
        -   mprotect(2) _(Disable DEP)_
        -   .bss Shellcode Execution
-   Bypassing ASLR
    -   Enumerating Memory Offset
        -   BlindSide Attack _(Meltdown Vulnerable CPUs)_
-   Use-After-Free
    -   Heap Spraying
-   JIT Spraying
-   Staged Shellcode
    -   Egg Hunting
-   Bypassing CFG
    -   Data-Oriented Attacks