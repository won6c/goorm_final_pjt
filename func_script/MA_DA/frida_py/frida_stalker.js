function getTimestamp() {
    return new Date().toISOString();
}

send({
    type: "ProcessEvent",
    event: "creation",
    pid: Process.id,
    timestamp: getTimestamp()
});

//Stalker
function stalkAllThreads() {
    var threads = Process.enumerateThreads();
    threads.forEach(function(thread) {
        send({
            type: "ThreadEvent",
            event: "existing",
            thread_id: thread.id,
            timestamp: getTimestamp()
        });
        Stalker.follow(thread.id, {
            events: {
                call: true,
                ret: false,
                exec: false,
                block: false,
                compile: false
            },
            onCallSummary: function(summary) {
                for (var target in summary) {
                    var sym = DebugSymbol.fromAddress(ptr(target));
                    var mod = Process.findModuleByAddress(ptr(target));
                    send({
                        type: "ThreadCall",
                        thread_id: thread.id,
                        target: sym.name,
                        address: target,
                        count: summary[target],
                        module:mod?mod.name : "unknown",
                        module_base:mod?mod.base.toString():"N/A",
                        timestamp: getTimestamp()
                    });
                }
            }
        });
        send({
            type: "info",
            message: "Stalker started on thread: " + thread.id,
            timestamp: getTimestamp()
        });
    });
}
stalkAllThreads();

var createThread = Module.findExportByName("kernel32.dll", "CreateThread");
if (createThread) {
    Interceptor.attach(createThread, {
       onEnter: function(args) {
           this.startRoutine = args[2];
           this.param = args[3];
           send({
               type: "CreateThread",
               event: "called",
               startRoutine: this.startRoutine.toString(),
               param: this.param.toString(),
               timestamp: getTimestamp()
           });
       },
       onLeave: function(retval) {
           if (!retval.isNull()) {
               var GetThreadId = new NativeFunction(Module.findExportByName("kernel32.dll", "GetThreadId"), 'uint', ['pointer']);
               var threadId = GetThreadId(retval);
               send({
                   type: "CreateThread",
                   event: "new_thread_created",
                   thread_id: threadId,
                   timestamp: getTimestamp()
               });
               send({
                   type: "ThreadEvent",
                   event: "creation",
                   thread_id: threadId,
                   timestamp: getTimestamp()
               });
               Stalker.follow(threadId, {
                   events: { call: true },
                   onCallSummary: function(summary) {
                       for (var target in summary) {
                           var sym = DebugSymbol.fromAddress(ptr(target));
                           send({
                               type: "NewThreadCall",
                               thread_id: threadId,
                               target: sym.name,
                               address: target,
                               count: summary[target],
                               timestamp: getTimestamp()
                           });
                       }
                   }
               });
               send({
                   type: "info",
                   message: "Stalker started on new thread: " + threadId,
                   timestamp: getTimestamp()
               });
           }
       }
    });
} else {
    send({
        type: "error",
        message: "CreateThread not found",
        timestamp: getTimestamp()
    });
}

var createProcessW = Module.findExportByName("kernel32.dll", "CreateProcessW");
if (createProcessW) {
    Interceptor.attach(createProcessW, {
       onEnter: function(args) {
           var appName = "";
           var cmdLine = "";
           if (!args[0].isNull()) {
               appName = Memory.readUtf16String(args[0]);
           }
           if (!args[1].isNull()) {
               cmdLine = Memory.readUtf16String(args[1]);
           }
           send({
               type: "CreateProcessW",
               event: "called",
               appName: appName,
               cmdLine: cmdLine,
               timestamp: getTimestamp()
           });
       },
       onLeave: function(retval) {
           send({
               type: "CreateProcessW",
               event: "returned",
               retval: retval.toString(),
               timestamp: getTimestamp()
           });
       }
    });
} else {
    send({
        type: "error",
        message: "CreateProcessW not found",
        timestamp: getTimestamp()
    });
}

var createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
if (createFileW) {
    Interceptor.attach(createFileW, {
       onEnter: function(args) {
           var fileName = Memory.readUtf16String(args[0]);
           send({
               type: "CreateFileW",
               event: "called",
               fileName: fileName,
               timestamp: getTimestamp()
           });
       }
    });
} else {
    send({
        type: "error",
        message: "CreateFileW not found",
        timestamp: getTimestamp()
    });
}

var writeFile = Module.findExportByName("kernel32.dll", "WriteFile");
if (writeFile) {
    Interceptor.attach(writeFile, {
       onEnter: function(args) {
           var buf = args[1];
           var size = args[2].toInt32();
           var content = Memory.readUtf8String(buf, size);
           send({
               type: "WriteFile",
               event: "called",
               bufferContent: content,
               timestamp: getTimestamp()
           });
       }
    });
} else {
    send({
        type: "error",
        message: "WriteFile not found",
        timestamp: getTimestamp()
    });
}

var exitThread = Module.findExportByName("kernel32.dll", "ExitThread");
if (exitThread) {
    Interceptor.attach(exitThread, {
        onEnter: function(args) {
            send({
                type: "ThreadEvent",
                event: "termination",
                thread_id: Process.getCurrentThreadId(),
                timestamp: getTimestamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "ExitThread not found",
        timestamp: getTimestamp()
    });
}

var exitProcess = Module.findExportByName("kernel32.dll", "ExitProcess");
if (exitProcess) {
    Interceptor.attach(exitProcess, {
        onEnter: function(args) {
            send({
                type: "ProcessEvent",
                event: "termination",
                pid: Process.id,
                timestamp: getTimestamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "ExitProcess not found",
        timestamp: getTimestamp()
    });
}