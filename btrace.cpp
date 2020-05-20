/*
 * Copyright 2002-2019 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

#include<bits/stdc++.h> 
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <algorithm>
#include <unordered_map> 
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <errno.h>

#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;
using std::hex;


#ifndef MAP_SYNC
#define MAP_SYNC 0x80000
#endif

#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0x03
#endif

using namespace std;

INT32 numThreads = 0;
ofstream fileptr;
FILE *file;

// map to maintain system call number and name for the calls handled by btrace
static map<int,string> syscalls;

// Data structure to store the system call information of each thread
class thread_data_t
{
  public:
    thread_data_t() : _syscall_encountered(0),_entrycount(0),_exitcount(0) {}
    UINT8 _syscall_encountered; // flag to check if system call is encountered
    UINT8 _syscall_num; // corresponding system call number
    UINT64 _entrycount; // variable to count number of times system call entered
    UINT64 _exitcount; // variable to count number of times system call exited
    map<int,int> counter;
};

// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY tls_key = INVALID_TLS_KEY;


VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    numThreads++;
    thread_data_t* tdata = new thread_data_t;
    if (PIN_SetThreadData(tls_key, tdata, threadid) == FALSE)
    {
        cerr << "PIN_SetThreadData failed" << endl;
        PIN_ExitProcess(1);
    }
}


void print_read(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx){
    char* ptr = (char*)ecx;
    // Print in strace style by printing max 32 chars and rest ...
    string buf="\"";
    int i=0;
    while(i<32 && *ptr!='\0'){
            if(*ptr=='\n')
                buf+="\\n";
            else if(*ptr=='\t')
                buf+="\\t";
            else if(*ptr=='\r')
                buf+="\\r";
            else
                buf+= *ptr;
            ptr++;
            ++i;
    }
    buf+="\"";
    if(*ptr!='\0')
        buf+="...";
    fileptr <<syscalls[eax]<<"("<<(int)ebx<<", "<<buf<<", "<<(int)edx<<")";
}

void print_write(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx){
    char* ptr = (char*)ecx;
    // Print in strace style by printing max 32 chars and rest ...
    string buf="\"";
    for(int i=0;i<min(32,(int)edx);++i){
            if(*ptr=='\n')
                buf+="\\n";
            else if(*ptr=='\t')
                buf+="\\t";
            else if(*ptr=='\r')
                buf+="\\r";
            else
                buf+= *ptr;
            ptr++;
    }
    buf+="\"";
    if(edx>32)
        buf+="...";
    fileptr <<syscalls[eax]<<"("<<dec<<(int)ebx<<", "<<buf<<", "<<dec<<(int)edx<<")";
}

void print_open(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx){

    unsigned long rem_flag = ecx;
    // This flag will be any one of the below 3 
    string flags = "O_RDONLY";
    if(ecx & O_WRONLY)
        flags = "O_WRONLY", rem_flag ^= O_WRONLY;
    else if(ecx & O_RDWR)
        flags = "O_RDWR", rem_flag ^= O_RDWR;

    // Optional flags for open system call, imporant ones handled
    // Rest ORed values stored in rem_flag to print as it is
    if(ecx & O_NONBLOCK)
        flags += " | O_NONBLOCK", rem_flag ^= O_NONBLOCK;
    if(ecx & O_LARGEFILE)
        flags += " | O_LARGEFILE", rem_flag ^= O_LARGEFILE;
    if(ecx & O_DIRECTORY)
        flags += " | O_DIRECTORY", rem_flag ^= O_DIRECTORY;
    if(ecx & O_EXCL)
        flags += " | O_EXCL", rem_flag ^= O_EXCL;
    if(ecx & O_CREAT)
        flags += " | O_CREAT", rem_flag ^= O_CREAT;
    if(ecx & O_APPEND)
        flags += " | O_APPEND", rem_flag ^= O_APPEND;
    if(ecx & O_TRUNC)
        flags += " | O_TRUNC", rem_flag ^= O_TRUNC;
    if(ecx & O_EXCL)
        flags += " | O_EXCL", rem_flag ^= O_EXCL;
    if(ecx & O_ASYNC)
        flags += " | O_ASYNC", rem_flag ^= O_ASYNC;
    if(ecx & O_DIRECT)
        flags += " | O_DIRECT", rem_flag ^= O_DIRECT;
    if(ecx & O_DSYNC)
        flags += " | O_DSYNC", rem_flag ^= O_DSYNC;
    if(ecx & O_CLOEXEC)
        flags += " | O_CLOEXEC", rem_flag ^= O_CLOEXEC;

    
    fileptr <<syscalls[eax]<<"(\""<<(char*) ebx<<"\","<<flags;

    if(rem_flag != 0){
        fileptr<<" | "<<hex<<rem_flag;
    }

     fileptr<<", "<<dec<<(int)edx<<")";
}

void print_close(ADDRINT eax,ADDRINT ebx){
     fileptr <<syscalls[eax]<<"("<<(unsigned int)ebx<<")";
}

void print_access(ADDRINT eax,ADDRINT ebx,ADDRINT ecx){
    string buf = "";
    // This mode can either be F_OK or ORed value of the below flags
    if(ecx==F_OK){
        buf = "F_OK";
    }else{
        if(ecx & R_OK)
            buf += "R_OK|";
        if(ecx & W_OK)
            buf += "W_OK|";
        if(ecx & X_OK)
            buf += "X_OK|";
        buf.pop_back();
    }
    

    fileptr <<syscalls[eax]<<"(\""<<(char*) ebx<<"\", "<<buf<<")";
}
void print_brk(ADDRINT eax,ADDRINT ebx){
    if((int)ebx!=0)
        fileptr <<syscalls[eax]<<"("<<(void*)ebx<<")";
    else
        fileptr <<syscalls[eax]<<"(NULL)";
}

void print_munmap(ADDRINT eax,ADDRINT ebx,ADDRINT ecx){
    fileptr <<syscalls[eax]<<"(0x"<<hex<<(unsigned long)ebx
    <<dec<<" , "<<(size_t)ecx<<")"; 
}

void print_mprotect(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx){

    //unpack flags
    fileptr<<syscalls[eax]<<"(0x"<<hex<<ebx<<dec<<" , "<<(size_t)ecx<<" , ";
    // This flag can either be PROT_NONE or ORed value of the below flags
    if(edx==0){
        fileptr<<"PROT_NONE)";
    }else{
        int rem_flag = edx;
        string prot_flags = "";
        if(edx & PROT_READ)
            prot_flags += "PROT_READ|", rem_flag ^=PROT_READ;
        if(edx & PROT_WRITE)
            prot_flags += "PROT_WRITE|", rem_flag ^=PROT_WRITE;
        if(edx & PROT_EXEC)
            prot_flags += "PROT_EXEC|", rem_flag ^=PROT_EXEC;
        prot_flags.pop_back();
        fileptr<<prot_flags;

        if(rem_flag!=0)
            fileptr<<"|"<<rem_flag;
        fileptr<<")";
    }
    
    
}

void print_mmap2(ADDRINT eax,ADDRINT ebx, ADDRINT ecx, 
    ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT ebp){
    
    if((int)ebx==0)
        fileptr <<syscalls[eax]<<"(NULL";
    else
        fileptr <<syscalls[eax]<<"("<<(void*)ebx;

    // unpack prot
    string prot_flags = "";
    // This flag can either be PROT_NONE or ORed value of the below flags
    if(edx==0){
        prot_flags = "PROT_NONE";
    }else{

        if(edx & PROT_READ)
            prot_flags += "PROT_READ|";
        if(edx & PROT_WRITE)
            prot_flags += "PROT_WRITE|";
        if(edx & PROT_EXEC)
            prot_flags += "PROT_EXEC|";
        prot_flags.pop_back();
    }
    
    //unpack flags
    int rem_flag = esi; // variable to keep the OR of the flags not handled by btrace
    string flags;
    if(esi & MAP_PRIVATE)
        flags = "MAP_PRIVATE", rem_flag^= MAP_PRIVATE;
    else if(esi & MAP_SHARED)
        flags = "MAP_SHARED", rem_flag ^=MAP_SHARED;
    else if(esi & MAP_SHARED_VALIDATE)
        flags = "MAP_SHARED_VALIDATE", rem_flag ^=MAP_SHARED_VALIDATE;
    
    // Handle the important/common optional flags
    if(esi & MAP_FIXED)
        flags+= "|MAP_FIXED", rem_flag^=MAP_FIXED;
    if(esi & MAP_ANONYMOUS)
        flags+= "|MAP_ANONYMOUS", rem_flag^=MAP_ANONYMOUS;
    if(esi & MAP_DENYWRITE)
        flags+= "|MAP_DENYWRITE", rem_flag^=MAP_DENYWRITE;

    long arg4 = (long)edi;
    long arg5 = (long)ebp;

    fileptr<<dec<<" , "<<(size_t)ecx<<" , "<<prot_flags<<" , ";
    // If any other flags are present just print their ORed value
    if(rem_flag!=0)
       fileptr<<flags<<"|"<<rem_flag<<" , "<<arg4<<")"; 
    else
       fileptr<<flags<<" , "<<arg4<<" , 0x"<<hex<<arg5<<")"; 
}


void print_clone(ADDRINT eax,ADDRINT ebx, ADDRINT ecx, 
    ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT ebp){

     fileptr <<syscalls[eax]<<"("<<(unsigned long)ebx<<" , "<<
    (unsigned long)ecx<<" , "<<(unsigned long)edx<<
    " , "<<(unsigned long)esi<<" , "<<(void*)edi<<" , "<<(void*)ebp<<")"; 

}

void print__llseek(ADDRINT eax,ADDRINT ebx, ADDRINT ecx, 
    ADDRINT edx, ADDRINT esi, ADDRINT edi){

    fileptr <<syscalls[eax]<<"("<<(unsigned int)ebx<<" , "<<
    (unsigned long)ecx<<" , "<<(unsigned long)edx<<" , "
    <<(void *)esi<<" , "<<(unsigned int)edi<<")"; 
}

void print_writev(ADDRINT eax,ADDRINT ebx, ADDRINT ecx, 
    ADDRINT edx){
    fileptr <<syscalls[eax]<<"("<<(unsigned long)ebx<<" , (struct address)"<<
    (void*)ecx<<" , "<<(unsigned long)edx<<")";
}

void print_fstat64(ADDRINT eax,ADDRINT ebx,ADDRINT ecx){
    fileptr <<syscalls[eax]<<"("<<(unsigned long)ebx<<
    " , (struct address)"<<(void *)ecx<<")"; 
}

void print_set_thread_area(ADDRINT eax,ADDRINT ebx){
    fileptr <<syscalls[eax]<<"((struct address)"<<(void *)ebx<<")"; 
}

void print_exit_group(ADDRINT eax, ADDRINT ebx){
    fileptr<<syscalls[eax]<<"("<<(int)ebx<<")"; 
}


void print_getdents64(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx){
    fileptr <<syscalls[eax]<<"("<<(unsigned long)ebx<<
    " , "<<(void *)ecx<<" , "<<(unsigned long)edx<<")"; 
}

void print_statfs64(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx){
    fileptr <<syscalls[eax]<<"(\""<<(char*)ebx<<
    "\" , "<<(size_t)ecx<<" , "<<(void*)edx<<")"; 
}

void print_ioctl(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx){
    fileptr <<syscalls[eax]<<"("<<(unsigned int)ebx<<
    " , "<<(unsigned int)ecx<<" , "<<(unsigned long)edx<<")"; 
}

void print_rt_sigaction(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx, ADDRINT esi){
    fileptr <<syscalls[eax]<<"("<<(int)ebx<<" , (struct address)"<<(void*)ecx<<" , ";
    if((int)edx == 0)
        fileptr<<"NULL , "<<(size_t)esi<<")"; 
    else
        fileptr<<"(struct address)"<<(void*)edx<<" , "<<(size_t)esi<<")"; 
}

void print_set_robust_list(ADDRINT eax,ADDRINT ebx,ADDRINT ecx){
    fileptr <<syscalls[eax]<<"("<<(void*)ebx<<" , "<<(size_t)ecx<<")"; 
}


void print_set_tid_address(ADDRINT eax,ADDRINT ebx){
    fileptr <<syscalls[eax]<<"("<<(int*)ebx<<")"; 
}

void print_uname(ADDRINT eax,ADDRINT ebx){
    fileptr <<syscalls[eax]<<"((struct address)"<<(void*)ebx<<")"; 
}

void print_rt_sigprocmask(ADDRINT eax,ADDRINT ebx,ADDRINT ecx, ADDRINT edx, ADDRINT esi){
    fileptr <<syscalls[eax]<<"("<<(int)ebx<<" , "<<(void*)ecx<<" , ";
    if((int)edx == 0)
        fileptr<<"NULL , "<<(size_t)esi<<")"; 
    else
        fileptr<<(void*)edx<<" , "<<(size_t)esi<<")";
}

void print_ugetrlimit(ADDRINT eax,ADDRINT ebx,ADDRINT ecx){
    fileptr <<syscalls[eax]<<"("<<(unsigned int)ebx<<" , (struct address)"<<(void*)ecx<<")"; 
}

void  print_poll(ADDRINT eax,ADDRINT ebx,ADDRINT ecx,ADDRINT edx){
    fileptr<<syscalls[eax]<<"((struct address)"<<(void*)ebx<<" , "<<
    (unsigned int)ecx<<" , "<<(long)edx<<")";
}

void print_futex(ADDRINT eax){
    fileptr<<syscalls[eax]<<"(...)";
}

void print_stat64(ADDRINT eax,ADDRINT ebx,ADDRINT ecx){
    fileptr<<syscalls[eax]<<"("<<(char*)ebx<<" , "<<(void*)ecx<<")";
}

// This function is called before every block
VOID syscall_start(THREADID threadid,CONTEXT* ctxt)
{ 

    // Get the value of all the registers which will have the system call parameters
    ADDRINT eax, ebx, ecx, edx, esi, edi,ebp;
    PIN_GetContextRegval(ctxt, REG_EAX, reinterpret_cast<UINT8*>(&eax));
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));
    PIN_GetContextRegval(ctxt, REG_ESI, reinterpret_cast<UINT8*>(&esi));
    PIN_GetContextRegval(ctxt, REG_EDI, reinterpret_cast<UINT8*>(&edi));
    PIN_GetContextRegval(ctxt, REG_EBP, reinterpret_cast<UINT8*>(&ebp));

    // Set the system encountered flag for the respective thread
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
    tdata->_syscall_encountered = true;
    tdata->_syscall_num = eax;
    tdata->_entrycount ++;

    // Following system calls are handled by btrace to print in strace format
    // For any other system call, other_system_call(...) will be printed
    switch(eax){
        case 3:
                print_read(eax,ebx,ecx,edx);
                break;
        case 4: 
                print_write(eax,ebx,ecx,edx);
                break;
        case 5:
                print_open(eax,ebx,ecx,edx);
                break;
        case 6:
                print_close(eax,ebx);
                break;
        case 33:
                print_access(eax,ebx,ecx);
                break;
        case 45:        
                print_brk(eax,ebx);
                break;
        case 54:
                print_ioctl(eax,ebx,ecx,edx);
                break;
        case 91: 
                print_munmap(eax,ebx,ecx);       
                break;
        case 120:
                print_clone(eax,ebx, ecx, edx, esi, edi, ebp);
                break;
        case 122:
                print_uname(eax,ebx);
                break;
        case 125:
                print_mprotect(eax,ebx,ecx,edx);
                break;
        case 140:
                print__llseek(eax,ebx, ecx, edx, esi, edi);
                break;
        case 146:
                print_writev(eax,ebx,ecx,edx);
                break;
        case 168: 
                print_poll(eax,ebx,ecx,edx);
                break;
        case 174:
                print_rt_sigaction(eax,ebx,ecx,edx,esi);
                break;
        case 175:
                print_rt_sigprocmask(eax,ebx,ecx,edx,esi);
                break;
        case 191:
                print_ugetrlimit(eax,ebx,ecx);
                break;
        case 192:
                print_mmap2(eax,ebx, ecx, edx, esi, edi, ebp);
                break;
        case 195:
                print_stat64(eax,ebx,ecx);
                break;
        case 197:
                print_fstat64(eax,ebx,ecx);
                break;
        case 220:
                print_getdents64(eax,ebx,ecx,edx);
                break;
        case 240:
                print_futex(eax);
                break;
        case 243:
                print_set_thread_area(eax,ebx);
                break;
        case 252: 
                print_exit_group(eax,ebx);
                break; 
        case 258:
                print_set_tid_address(eax,ebx);
                break;
        case 268:
                print_statfs64(eax,ebx,ecx,edx);
                break;
        case 311:
                print_set_robust_list(eax,ebx,ecx);
                break;
        default:
            // Any other system call not handled by btrace
            fileptr<<"other_system_call(...) ";
            break;

    }
}



VOID syscall_end(THREADID threadid,const CONTEXT * ctxt) { 

    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
    
    // For each thread check if system encountered flag is set
    // If yes then print the return value
    if(tdata->_syscall_encountered){

        ADDRINT val1;
        PIN_GetContextRegval(ctxt, REG_EAX, reinterpret_cast<UINT8*>(&val1));
        // 
        if(tdata->_syscall_num == 33 || tdata->_syscall_num == 5){
            int val = val1;
            // Kernel returns error code, print the corresponding error and return -1
            if(val < 0 && val > -4096) {
                string buf = " = -1 ";
                bool f = false;
                val *=-1; // variable to store any other error not handled by btrace
                if(val== ENOENT)
                    buf += " ENOENT (No such file or directory)";
                else if(val== ENOTDIR)
                    buf += "ENOTDIR (Not a directory)";
                else if(val == EACCES)
                    buf += "EACCES (Permission denied)";
                else if(val == ELOOP)
                    buf += "ELOOP (Too many levels of symbolic links)";
                else if(val == ENAMETOOLONG)
                    buf += "ENAMETOOLONG (Filename too long)";
                else if(val == EROFS)
                    buf += "EROFS (Read-only filesystem)";
                else if(val== EIO)
                    buf += "EIO (Input/output error)";
                else {
                    f = true;
                    buf = buf + "(Errorno: ";
                }
                // Check if some other issue then print the error no
                if(f)
                    fileptr<<buf<<dec<<val<<")"<<endl;
                else
                    fileptr<<buf<<endl;
            }else
                fileptr<<" = "<<dec<<val<<endl;
        }
        // For mmap2 and brk return the address
        else if(tdata->_syscall_num == 192 || tdata->_syscall_num == 45)
            fileptr << " = " <<(void*)val1 << endl;
        else
            fileptr << " = " << (long)val1 << endl;
        
        // Reset the system call encountered flag
        tdata->_syscall_encountered = false;
        tdata->_exitcount++;
    }

}


// Pin calls this function every time a new basic block is encountered
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block  in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Instrument first instruction of every bb to check if it is end of a system call
        INS ins = BBL_InsHead(bbl);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)syscall_end,
                IARG_THREAD_ID,
                IARG_CONST_CONTEXT,IARG_END);
       
        // Check the last instruction of a bb if it is a system call
        // If yes, then add the instrumentation to display system call parameters
        INS lastIns = BBL_InsTail(bbl);
        if(INS_IsSyscall(lastIns)){
           
            // Arguments and syscall number is only available before
        INS_InsertCall(lastIns, IPOINT_BEFORE, AFUNPTR(syscall_start),
                       IARG_THREAD_ID,
                       IARG_CONST_CONTEXT,
                       IARG_END);
        }
    }
}



KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "btrace.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    fileptr.setf(ios::showbase);
    // fileptr << "Syscalls Count " << icount << endl;
    // fprintf(file, "Syscalls entry: %llu, Syscalls exit: %llu\n", entrycount,exitcount);
    fileptr.close();
    fclose(file);
}

// This function is called when the thread exits
VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadIndex));
    // fileptr << "\nCount[" << decstr(threadIndex) << "] = "<<" entrycount: "<<
    // tdata->_entrycount<<" , exitcount: "<<tdata->_exitcount;
    delete tdata;
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

void add_syscalls(){

    syscalls.insert(pair<int,string>(3,"read"));
    syscalls.insert(pair<int,string>(4,"write"));
    syscalls.insert(pair<int,string>(5,"open"));
    syscalls.insert(pair<int,string>(6,"close"));
    syscalls.insert(pair<int,string>(33,"access"));
    syscalls.insert(pair<int,string>(45,"brk"));
    syscalls.insert(pair<int,string>(54,"ioctl"));
    syscalls.insert(pair<int,string>(91,"munmap"));

    syscalls.insert(pair<int,string>(120,"clone"));
    syscalls.insert(pair<int,string>(122,"uname"));
    syscalls.insert(pair<int,string>(125,"mprotect"));
    syscalls.insert(pair<int,string>(140,"_llseek"));
    syscalls.insert(pair<int,string>(146,"writev"));
    syscalls.insert(pair<int,string>(168,"poll"));
    syscalls.insert(pair<int,string>(174,"rt_sigaction"));
    syscalls.insert(pair<int,string>(175,"rt_sigprocmask"));

    syscalls.insert(pair<int,string>(191,"ugetrlimit"));
    syscalls.insert(pair<int,string>(192,"mmap2"));
    syscalls.insert(pair<int,string>(195,"stat64"));
    syscalls.insert(pair<int,string>(197,"fstat64"));
    syscalls.insert(pair<int,string>(220,"getdents64"));
    syscalls.insert(pair<int,string>(240,"futex"));

    syscalls.insert(pair<int,string>(243,"set_thread_area"));
    syscalls.insert(pair<int,string>(252,"exit_group"));
    syscalls.insert(pair<int,string>(258,"set_tid_address"));
    syscalls.insert(pair<int,string>(268,"statfs64"));
    syscalls.insert(pair<int,string>(311,"set_robust_list"));
    



}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{

    add_syscalls();

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();

    file = fopen("btrace1.out","w");

    fileptr.open(KnobOutputFile.Value().c_str());

    // Obtain  a key for TLS storage.
    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << endl;
        PIN_ExitProcess(1);
    }

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    // Register Fini to be called when thread exits.
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}