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

#include <iostream>
#include <fstream>
#include <algorithm>
#include <limits.h>
#include<bits/stdc++.h> 
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;
using std::hex;
using std::dec;

ofstream fileptr;
std::ostream * out = &cerr;

INT32 numThreads = 0;

// Thread data structure to store data for each thread
class thread_data_t
{
  public:
    thread_data_t(ADDRINT base) :  _max_esp(base),_min_esp(base),_diff(0) {}
    ADDRINT _max_esp; // variable to store max esp
    ADDRINT _min_esp;  // variable to store min esp
    int _diff;  // variable to store max stack usage
};

// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY tls_key = INVALID_TLS_KEY;

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    numThreads++;
    thread_data_t* tdata = new thread_data_t(PIN_GetContextReg(ctxt, REG_STACK_PTR));
    if (PIN_SetThreadData(tls_key, tdata, threadid) == FALSE)
    {
        cerr << "PIN_SetThreadData failed" << endl;
        PIN_ExitProcess(1);
    }
}

VOID checkEspUpdated(const CONTEXT * ctxt, THREADID threadid) { 

    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
    
    ADDRINT esp;
    PIN_GetContextRegval(ctxt, REG_ESP, reinterpret_cast<UINT8*>(&esp));

    // Check for both upper and lower bounds of where the esp can point
    if(tdata->_min_esp>esp){
        // If esp is way below min_esp, it might point to heap 
        // so stack pivoting and exit program
        if(tdata->_min_esp - esp > 50000){
            fileptr<<"ThreadId: "<<threadid<<" Stack pivoting detected!! exit program"<<endl;
            exit(-1);
        }else{
            tdata->_min_esp = esp;
        }
    }
    if(tdata->_max_esp<esp){
        // If esp is way above max_esp, it might point to pivoted attacker address
        // so stack pivoting and exit program
        if(esp - tdata-> _max_esp>= 5000){
            fileptr<<"ThreadId: "<<threadid<<" Stack pivoting detected!! exit program"<<endl;
            exit(-1);
        }else{
            tdata->_max_esp = esp;
        }
    }
    // Update max stack used till now
    tdata->_diff = tdata->_max_esp - tdata->_min_esp;
 
}
    
VOID Instruction(INS ins, VOID *v)
{
    // Instrument every instruction which modifies the esp
    // Point after every such instruction to get updated esp value
    // and do bounds check for dectecting stack pivoting.
    if(INS_RegWContain(ins,REG_STACK_PTR) && INS_IsValidForIpointAfter(ins)){
        INS_InsertCall(ins,
                   IPOINT_AFTER,
                   AFUNPTR(checkEspUpdated),
                   IARG_CONST_CONTEXT,
                   IARG_THREAD_ID,
                   IARG_END);
    }
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "stackpivot.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    fileptr.setf(ios::showbase);
    fileptr.close();
}

// This function is called when the thread exits
VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadIndex));
    fileptr << "Max stack size[" << decstr(threadIndex) << "] = "<<
    dec<<(int)tdata->_diff<<" or 0x"<<hex<<(int)tdata->_diff<<
    " No stack pivoting detected!"<<endl;
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

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    fileptr.open(KnobOutputFile.Value().c_str());

    // Obtain  a key for TLS storage.
    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << endl;
        PIN_ExitProcess(1);
    }

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

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
