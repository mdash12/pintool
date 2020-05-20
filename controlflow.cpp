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
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;

ofstream OutFile;

// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 dcount = 0;
static UINT64 indcount = 0;
static UINT64 rcount = 0;
PIN_LOCK pinLock;
FILE *out;

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&pinLock, threadid+1);
    fprintf(out, "thread begin %d\n",threadid);
    fflush(out);
    PIN_ReleaseLock(&pinLock);
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    PIN_GetLock(&pinLock, threadid+1);
    fprintf(out, "thread end %d code %d\n",threadid, code);
    fflush(out);
    PIN_ReleaseLock(&pinLock);
}

// This function is called before every block
VOID directcount(THREADID threadid) { 
    PIN_GetLock(&pinLock, threadid+1);
    dcount ++;
    PIN_ReleaseLock(&pinLock);
}
    
VOID indirectcount(THREADID threadid) {
    PIN_GetLock(&pinLock, threadid+1);
    indcount ++;
    PIN_ReleaseLock(&pinLock);
}

VOID remainingcount(THREADID threadid) {
    PIN_GetLock(&pinLock, threadid+1);
    rcount ++;
    PIN_ReleaseLock(&pinLock);
}


// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block  in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // For every bb check if the last ins is a direct control transfer or indirect control transfer
        INS lastIns = BBL_InsTail(bbl);
        if(INS_IsDirectControlFlow(lastIns) || INS_IsDirectBranch(lastIns) 
            || INS_IsDirectCall(lastIns)){
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)directcount,IARG_THREAD_ID,IARG_END);
        }else if(INS_IsIndirectControlFlow(lastIns) || INS_IsRet (lastIns)){
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)indirectcount,IARG_THREAD_ID,IARG_END);
        }else{
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)remainingcount,IARG_THREAD_ID,IARG_END);
        }
       
    }
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "controlflow.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Direct Count " << dcount << endl;
    OutFile << "InDirect Count " << indcount << endl;
    OutFile << "Remaining Count " << rcount << endl;
    OutFile.close();
    fclose(out);
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

int main(int argc, char * argv[])
{
    PIN_InitLock(&pinLock);
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();

    out = fopen("controlflow1.out","w");
    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
