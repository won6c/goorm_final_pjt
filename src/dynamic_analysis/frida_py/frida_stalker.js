function getTimeStamp() {
    return new Date().toISOString();
}

send({
    type: "ProcessEvent",
    event: "creation",
    pid: Process.id,
    timestamp: getTimeStamp()
});

//Stalker
function stalkAllThreads() {
    var threads = Process.enumerateThreads();
    threads.forEach(function(thread) {
        send({
            type: "ThreadEvent",
            event: "existing",
            thread_id: thread.id,
            timestamp: getTimeStamp()
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
                        timestamp: getTimeStamp()
                    });
                }
            }
        });
        send({
            type: "info",
            message: "Stalker started on thread: " + thread.id,
            timestamp: getTimeStamp()
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
               timestamp: getTimeStamp()
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
                   timestamp: getTimeStamp()
               });A
               send({
                   type: "ThreadEvent",
                   event: "creation",
                   thread_id: threadId,
                   timestamp: getTimeStamp()
               });
               Stalker.follow(threadId, {
                   events: { call: true },
                   onCallSummary: function(summary) {
                       for (var target in summary) {
                           var sym = DebugSymbol.fromAddress(ptr(target));
                           var mod = Process.findModuleByAddress(ptr(target));
                           send({
                               type: "ThreadCall",
                               thread_id: threadId,
                               target: sym.name,
                               address: target,
                               count: summary[target],
                               module:mod?mod.name : "unknown",
                               module_base:mod?mod.base.toString():"N/A",
                               timestamp: getTimeStamp()
                           });
                       }
                   }
               });
               send({
                   type: "info",
                   message: "Stalker started on new thread: " + threadId,
                   timestamp: getTimeStamp()
               });
           }
       }
    });
} else {
    send({
        type: "error",
        message: "CreateThread not found",
        timestamp: getTimeStamp()
    });
}


// CreateFileA 
var createFileA = Module.findExportByName("kernel32.dll", "CreateFileA");
if (createFileA) {
    Interceptor.attach(createFileA, {
        onEnter: function(args) {
            var fileNameA = Memory.readCString(args[0]);
            send({
                type: "CreateFileA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                fileName: fileNameA,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CreateFileW 
var createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
if (createFileW) {
    Interceptor.attach(createFileW, {
        onEnter: function(args) {
            var fileNameW = Memory.readUtf16String(args[0]);
            send({
                type: "CreateFileW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                fileName: fileNameW,
                timestamp: getTimeStamp()
            });
        }
    });
}

// WriteFile
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
                thread_id: Process.getCurrentThreadId(),
                timestamp: getTimeStamp()
            });
        }
    });
}

// WriteFileEx 
var writeFileEx = Module.findExportByName("kernel32.dll", "WriteFileEx");
if (writeFileEx) {
    Interceptor.attach(writeFileEx, {
        onEnter: function(args) {
            var buf = args[1];
            var size = args[2].toInt32();
            var content = Memory.readUtf8String(buf, size);
            send({
                type: "WriteFileEx",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                bufferContent: content,
                timestamp: getTimeStamp()
            });
        }
    });
}

// DeleteFileA
var deleteFileA = Module.findExportByName("kernel32.dll", "DeleteFileA");
if (deleteFileA) {
    Interceptor.attach(deleteFileA, {
        onEnter: function(args) {
            var fileNameA = Memory.readCString(args[0]);
            send({
                type: "DeleteFileA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                fileName: fileNameA,
                timestamp: getTimeStamp()
            });
        }
    });
}

// DeleteFileW 
var deleteFileW = Module.findExportByName("kernel32.dll", "DeleteFileW");
if (deleteFileW) {
    Interceptor.attach(deleteFileW, {
        onEnter: function(args) {
            var fileNameW = Memory.readUtf16String(args[0]);
            send({
                type: "DeleteFileW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                fileName: fileNameW,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CreateProcessA
var createProcessA = Module.findExportByName("kernel32.dll", "CreateProcessA");
if (createProcessA) {
    Interceptor.attach(createProcessA, {
        onEnter: function(args) {
            var appName = "";
            var cmdLine = "";
            if (!args[0].isNull()) {
                appName = Memory.readCString(args[0]);
            }
            if (!args[1].isNull()) {
                cmdLine = Memory.readCString(args[1]);
            }
            send({
                type: "CreateProcessA",
                event: "called",
                appName: appName,
                cmdLine: cmdLine,
                timestamp: getTimeStamp()
            });
        },
        onLeave: function(retval) {
            send({
                type: "CreateProcessA",
                event: "returned",
                retval: retval.toString(),
                timestamp: getTimeStamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "CreateProcessA not found",
        timestamp: getTimeStamp()
    });
}

// CreateProcessW
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
                timestamp: getTimeStamp()
            });
        },
        onLeave: function(retval) {
            send({
                type: "CreateProcessW",
                event: "returned",
                retval: retval.toString(),
                timestamp: getTimeStamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "CreateProcessW not found",
        timestamp: getTimeStamp()
    });
}

// CreateProcessAsUserA
var createProcessAsUserA = Module.findExportByName("kernel32.dll", "CreateProcessAsUserA");
if (createProcessAsUserA) {
    Interceptor.attach(createProcessAsUserA, {
        onEnter: function(args) {
            var appName = "";
            var cmdLine = "";
            if (!args[1].isNull()) {
                appName = Memory.readCString(args[1]);
            }
            if (!args[2].isNull()) {
                cmdLine = Memory.readCString(args[2]);
            }
            send({
                type: "CreateProcessAsUserA",
                event: "called",
                appName: appName,
                cmdLine: cmdLine,
                timestamp: getTimeStamp()
            });
        },
        onLeave: function(retval) {
            send({
                type: "CreateProcessAsUserA",
                event: "returned",
                retval: retval.toString(),
                timestamp: getTimeStamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "CreateProcessAsUserA not found",
        timestamp: getTimeStamp()
    });
}

// CreateProcessAsUserW
var createProcessAsUserW = Module.findExportByName("kernel32.dll", "CreateProcessAsUserW");
if (createProcessAsUserW) {
    Interceptor.attach(createProcessAsUserW, {
        onEnter: function(args) {
            var appName = "";
            var cmdLine = "";
            if (!args[1].isNull()) {
                appName = Memory.readUtf16String(args[1]);
            }
            if (!args[2].isNull()) {
                cmdLine = Memory.readUtf16String(args[2]);
            }
            send({
                type: "CreateProcessAsUserW",
                event: "called",
                appName: appName,
                cmdLine: cmdLine,
                timestamp: getTimeStamp()
            });
        },
        onLeave: function(retval) {
            send({
                type: "CreateProcessAsUserW",
                event: "returned",
                retval: retval.toString(),
                timestamp: getTimeStamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "CreateProcessAsUserW not found",
        timestamp: getTimeStamp()
    });
}

// CreateProcessWithLogonW
var createProcessWithLogonW = Module.findExportByName("kernel32.dll", "CreateProcessWithLogonW");
if (createProcessWithLogonW) {
    Interceptor.attach(createProcessWithLogonW, {
        onEnter: function(args) {
            var userName = Memory.readUtf16String(args[0]);
            var domain = Memory.readUtf16String(args[1]);
            var password = Memory.readUtf16String(args[2]);
            var appName = Memory.readUtf16String(args[4]);
            var cmdLine = Memory.readUtf16String(args[5]);
            var currentDir = Memory.readUtf16String(args[8]);
            send({
                type: "CreateProcessWithLogonW",
                event: "called",
                user: userName,
                pass: password,
                domain: domain,
                appName: appName,
                cmdLine: cmdLine,
                currentDir: currentDir,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CreateProcessWithTokenW
var createProcessWithTokenW = Module.findExportByName("kernel32.dll", "CreateProcessWithTokenW");
if (createProcessWithTokenW) {
    Interceptor.attach(createProcessWithTokenW, {
        onEnter: function(args) {
            var appName = Memory.readUtf16String(args[2]);
            var cmdLine = Memory.readUtf16String(args[3]);
            var currentDir = Memory.readUtf16String(args[6]);
            send({
                type: "CreateProcessWithTokenW",
                event: "called",
                appName: appName,
                cmdLine: cmdLine,
                currentDir: currentDir,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ExitProcess
var exitProcess = Module.findExportByName("kernel32.dll", "ExitProcess");
if (exitProcess) {
    Interceptor.attach(exitProcess, {
        onEnter: function(args) {
            send({
                type: "ProcessEvent",
                event: "termination",
                pid: Process.id,
                timestamp: getTimeStamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "ExitProcess not found",
        timestamp: getTimeStamp()
    });
}

var isdbgpr = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
if (isdbgpr) {
    Interceptor.attach(isdbgpr, {
        onEnter: function(){  
        },
        onLeave: function(retval){
            retval.replace(0);
        }
    });
}

// ExitThread
var exitThread = Module.findExportByName("kernel32.dll", "ExitThread");
if (exitThread) {
    Interceptor.attach(exitThread, {
        onEnter: function(args) {
            send({
                type: "ThreadEvent",
                event: "termination",
                thread_id: Process.getCurrentThreadId(),
                timestamp: getTimeStamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "ExitThread not found",
        timestamp: getTimeStamp()
    });
}

// GetModuleHandleA
var getModuleHandleA = Module.findExportByName("kernel32.dll", "GetModuleHandleA");
if (getModuleHandleA) {
    Interceptor.attach(getModuleHandleA, {
        onEnter: function(args) {
            var moduleName = Memory.readCString(args[0]);
            send({
                type: "GetModuleHandleA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                moduleName: moduleName,
                timestamp: getTimeStamp()
            });
        }
    });
}

// GetModuleHandleW
var getModuleHandleW = Module.findExportByName("kernel32.dll", "GetModuleHandleW");
if (getModuleHandleW) {
    Interceptor.attach(getModuleHandleW, {
        onEnter: function(args) {
            var moduleName = Memory.readUtf16String(args[0]);
            send({
                type: "GetModuleHandleW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                moduleName: moduleName,
                timestamp: getTimeStamp()
            });
        }
    });
}

// GetModuleHandleExA
var getModuleHandleExA = Module.findExportByName("kernel32.dll", "GetModuleHandleExA");
if (getModuleHandleExA) {
    Interceptor.attach(getModuleHandleExA, {
        onEnter: function(args) {
            var moduleName = Memory.readCString(args[1]);
            send({
                type: "GetModuleHandleExA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                moduleName: moduleName,
                timestamp: getTimeStamp()
            });
        }
    });
}

// GetModuleHandleExW
var getModuleHandleExW = Module.findExportByName("kernel32.dll", "GetModuleHandleExW");
if (getModuleHandleExW) {
    Interceptor.attach(getModuleHandleExW, {
        onEnter: function(args) {
            var moduleName = Memory.readUtf16String(args[1]);
            send({
                type: "GetModuleHandleExW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                moduleName: moduleName,
                timestamp: getTimeStamp()
            });
        }
    });
}

// GetModuleFileNameA
var getModuleFileNameA = Module.findExportByName("kernel32.dll", "GetModuleFileNameA");
if (getModuleFileNameA) {
    Interceptor.attach(getModuleFileNameA, {
        onEnter: function(args) {
            var fileName = Memory.readCString(args[1]);
            send({
                type: "GetModuleFileNameA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                fileName: fileName,
                timestamp: getTimeStamp()
            });
        }
    });
}

// GetModuleFileNameW
var getModuleFileNameW = Module.findExportByName("kernel32.dll", "GetModuleFileNameW");
if (getModuleFileNameW) {
    Interceptor.attach(getModuleFileNameW, {
        onEnter: function(args) {
            var fileName = Memory.readUtf16String(args[1]);
            send({
                type: "GetModuleFileNameW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                fileName: fileName,
                timestamp: getTimeStamp()
            });
        }
    });
}

// LoadLibraryA
var loadLibraryA = Module.findExportByName("kernel32.dll", "LoadLibraryA");
if (loadLibraryA) {
    Interceptor.attach(loadLibraryA, {
        onEnter: function(args) {
            var lib = Memory.readCString(args[0]);
            send({
                type: "LoadLibraryA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                lpLibFileName: lib,
                timestamp: getTimeStamp()
            });
        }
    });
}

// LoadLibraryW
var loadLibraryW = Module.findExportByName("kernel32.dll", "LoadLibraryW");
if (loadLibraryW) {
    Interceptor.attach(loadLibraryW, {
        onEnter: function(args) {
            var lib = Memory.readUtf16String(args[0]);
            send({
                type: "LoadLibraryW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                lpLibFileName: lib,
                timestamp: getTimeStamp()
            });
        }
    });
}

// LoadLibraryExA
var loadLibraryExA = Module.findExportByName("kernel32.dll", "LoadLibraryExA");
if (loadLibraryExA) {
    Interceptor.attach(loadLibraryExA, {
        onEnter: function(args) {
            var lib = Memory.readCString(args[0]);
            var flag = args[2].toInt32();
            send({
                type: "LoadLibraryExA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                lpLibFileName: lib,
                Flags: flag,
                timestamp: getTimeStamp()
            });
        }
    });
}

// LoadLibraryExW
var loadLibraryExW = Module.findExportByName("kernel32.dll", "LoadLibraryExW");
if (loadLibraryExW) {
    Interceptor.attach(loadLibraryExW, {
        onEnter: function(args) {
            var lib = Memory.readUtf16String(args[0]);
            var flag = args[2].toInt32();
            send({
                type: "LoadLibraryExW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                lpLibFileName: lib,
                Flags: flag,
                timestamp: getTimeStamp()
            });
        }
    });
}

// LoadPackagedLibrary
var loadPackagedLibrary = Module.findExportByName("kernel32.dll", "LoadPackagedLibrary");
if (loadPackagedLibrary) {
    Interceptor.attach(loadPackagedLibrary, {
        onEnter: function(args) {
            var lib = Memory.readUtf16String(args[0]);
            send({
                type: "LoadPackagedLibrary",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                lpwLibFileName: lib,
                timestamp: getTimeStamp()
            });
        }
    });
}

var hookedAPIs = {};

// GetProcAddress 후킹
var getProcAddress = Module.findExportByName("kernel32.dll", "GetProcAddress");
if (getProcAddress) {
    Interceptor.attach(getProcAddress, {
        onEnter: function(args) {
            var moduleName = "unknown";
            try {
                var mod = Process.findModuleByAddress(ptr(args[0]));
                if (mod) {
                    moduleName = mod.name;
                }
            } catch (e) {}
            
            var api = "unknown";
            if (args[1].isNull()) {
                return;
            }
            
            try {
                var modForApi = Process.findModuleByAddress(ptr(args[1]));
                if (modForApi && modForApi.name.toLowerCase().indexOf("frida_agent.dll") !== -1) {
                    return;
                }
            } catch (e) {

            }
            
            try {
                api = Memory.readCString(args[1]);
            } catch (e) {
                return;
            }
            
            this.apiName = api; 
            send({
                type: "GetProcAddress",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                module: moduleName,
                procName: api,
                timestamp: getTimeStamp()
            });
        }
    });
} else {

}


// CreateServiceA
var createServiceA = Module.findExportByName("advapi32.dll", "CreateServiceA");
if (createServiceA) {
    Interceptor.attach(createServiceA, {
        onEnter: function(args) {
            var serviceName = Memory.readCString(args[1]);
            var displayName = Memory.readCString(args[2]);
            var serviceType = args[4].toInt32();
            var startType = args[5].toInt32();
            var binPath = Memory.readCString(args[7]);
            var dependencies = Memory.readCString(args[10]);
            var serviceStartName = Memory.readCString(args[11]);
            var pass = Memory.readCString(args[12]);
            send({
                type: "CreateServiceA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                ServiceName: serviceName,
                DisplayName: displayName,
                ServiceType: serviceType,
                StartType: startType,
                lpBinaryPathName: binPath,
                lpDependencies: dependencies,
                lpServiceStartName: serviceStartName,
                lpPassword: pass,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CreateServiceW
var createServiceW = Module.findExportByName("advapi32.dll", "CreateServiceW");
if (createServiceW) {
    Interceptor.attach(createServiceW, {
        onEnter: function(args) {
            var serviceName = Memory.readUtf16String(args[1]);
            var displayName = Memory.readUtf16String(args[2]);
            var serviceType = args[4].toInt32();
            var startType = args[5].toInt32();
            var binPath = Memory.readUtf16String(args[7]);
            var dependencies = Memory.readUtf16String(args[10]);
            var serviceStartName = Memory.readUtf16String(args[11]);
            var pass = Memory.readUtf16String(args[12]);
            send({
                type: "CreateServiceW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                ServiceName: serviceName,
                DisplayName: displayName,
                ServiceType: serviceType,
                StartType: startType,
                lpBinaryPathName: binPath,
                lpDependencies: dependencies,
                lpServiceStartName: serviceStartName,
                lpPassword: pass,
                timestamp: getTimeStamp()
            });
        }
    });
}

// RegOpenKeyExA
var regOpenKeyExA = Module.findExportByName("advapi32.dll", "RegOpenKeyExA");
if (regOpenKeyExA) {
    Interceptor.attach(regOpenKeyExA, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var subKey = Memory.readCString(args[1]);
            send({
                type: "RegOpenKeyExA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// RegOpenKeyExW
var regOpenKeyExW = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
if (regOpenKeyExW) {
    Interceptor.attach(regOpenKeyExW, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var subKey = Memory.readUtf16String(args[1]);
            send({
                type: "RegOpenKeyExW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// RegCreateKeyExA
var regCreateKeyExA = Module.findExportByName("advapi32.dll", "RegCreateKeyExA");
if (regCreateKeyExA) {
    Interceptor.attach(regCreateKeyExA, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var subKey = Memory.readCString(args[1]);
            send({
                type: "RegCreateKeyExA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// RegCreateKeyExW
var regCreateKeyExW = Module.findExportByName("advapi32.dll", "RegCreateKeyExW");
if (regCreateKeyExW) {
    Interceptor.attach(regCreateKeyExW, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var subKey = Memory.readUtf16String(args[1]);
            send({
                type: "RegCreateKeyExW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// RegDeleteValueA
var regDeleteValueA = Module.findExportByName("advapi32.dll", "RegDeleteValueA");
if (regDeleteValueA) {
    Interceptor.attach(regDeleteValueA, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var subKey = Memory.readCString(args[1]);
            send({
                type: "RegDeleteValueA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// RegDeleteValueW
var regDeleteValueW = Module.findExportByName("advapi32.dll", "RegDeleteValueW");
if (regDeleteValueW) {
    Interceptor.attach(regDeleteValueW, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var subKey = Memory.readUtf16String(args[1]);
            send({
                type: "RegDeleteValueW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// RegDeleteKeyExA
var regDeleteKeyExA = Module.findExportByName("advapi32.dll", "RegDeleteKeyExA");
if (regDeleteKeyExA) {
    Interceptor.attach(regDeleteKeyExA, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var subKey = Memory.readCString(args[1]);
            send({
                type: "RegDeleteKeyExA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// RegDeleteKeyExW
var regDeleteKeyExW = Module.findExportByName("advapi32.dll", "RegDeleteKeyExW");
if (regDeleteKeyExW) {
    Interceptor.attach(regDeleteKeyExW, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var subKey = Memory.readUtf16String(args[1]);
            send({
                type: "RegDeleteKeyExW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CryptAcquireContextA
var cryptAcquireContextA = Module.findExportByName("advapi32.dll", "CryptAcquireContextA");
if (cryptAcquireContextA) {
    Interceptor.attach(cryptAcquireContextA, {
        onEnter: function(args) {
            var container = Memory.readCString(args[1]);
            var provider = Memory.readCString(args[2]);
            var provType = args[3].toInt32();
            send({
                type: "CryptAcquireContextA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                container: container,
                provider: provider,
                provType: provType,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CryptAcquireContextW
var cryptAcquireContextW = Module.findExportByName("advapi32.dll", "CryptAcquireContextW");
if (cryptAcquireContextW) {
    Interceptor.attach(cryptAcquireContextW, {
        onEnter: function(args) {
            var container = Memory.readUtf16String(args[1]);
            var provider = Memory.readUtf16String(args[2]);
            var provType = args[3].toInt32();
            send({
                type: "CryptAcquireContextW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                container: container,
                provider: provider,
                provType: provType,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CryptEncrypt
var cryptEncrypt = Module.findExportByName("advapi32.dll", "CryptEncrypt");
if (cryptEncrypt) {
    Interceptor.attach(cryptEncrypt, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var hHash = args[1].toInt32();
            var isFinal = args[2].toInt32();
            var dwFlags = args[3].toInt32();
            var pbData = args[4];
            var pdwDataLen = args[5];
            var dwBufLen = args[6].toInt32();
            send({
                type: "CryptEncrypt",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                hHash: hHash,
                isFinal: isFinal,
                dwFlags: dwFlags,
                pbData: Memory.readByteArray(pbData, dwBufLen),
                pdwDataLen: Memory.readUInt(pdwDataLen),
                dwBufLen: dwBufLen,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CryptDecrypt
var cryptDecrypt = Module.findExportByName("advapi32.dll", "CryptDecrypt");
if (cryptDecrypt) {
    Interceptor.attach(cryptDecrypt, {
        onEnter: function(args) {
            var hKey = args[0].toInt32();
            var hHash = args[1].toInt32();
            var isFinal = args[2].toInt32();
            var dwFlags = args[3].toInt32();
            var pbData = args[4];
            var pdwDataLen = args[5];
            var dataLen = Memory.readUInt(pdwDataLen);
            send({
                type: "CryptDecrypt",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hKey: hKey,
                hHash: hHash,
                isFinal: isFinal,
                dwFlags: dwFlags,
                pbData: Memory.readByteArray(pbData, dataLen),
                pdwDataLen: dataLen,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CryptCreateHash
var cryptCreateHash = Module.findExportByName("advapi32.dll", "CryptCreateHash");
if (cryptCreateHash) {
    Interceptor.attach(cryptCreateHash, {
        onEnter: function(args) {
            var alg_id = args[1].toInt32();
            var hKey = args[2].toInt32();
            send({
                type: "CryptCreateHash",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                Algid: alg_id,
                hKey: hKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// CryptHashData
var cryptHashData = Module.findExportByName("advapi32.dll", "CryptHashData");
if (cryptHashData) {
    Interceptor.attach(cryptHashData, {
        onEnter: function(args) {
            var pbData = Memory.readByteArray(args[1], args[2].toInt32());
            send({
                type: "CryptHashData",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                pbData: pbData,
                timestamp: getTimeStamp()
            });
        }
    });
}

// AttachThreadInput
var attachThreadInput = Module.findExportByName("user32.dll","AttachThreadInput");
if (attachThreadInput) {
    Interceptor.attach(attachThreadInput, {
        onEnter: function(args){
            var idAttach = args[0].toInt32();
            var idAttachTo = args[1].toInt32();
            var fAttach = args[2].toInt32();
            send({
                type:"AttachThreadInput",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                idAttach: idAttach,
                idAttachTo: idAttachTo,
                fAttach: fAttach,
                timestamp: getTimeStamp()
            });
        }
    });
}

// GetKeyState
var getKeyState = Module.findExportByName("user32.dll","GetKeyState");
if (getKeyState) {
    Interceptor.attach(getKeyState, {
        onEnter: function(args){
            var nVirtKey = args[0].toInt32();
            send({
                type:"GetKeyState",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                nVirtKey: nVirtKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// GetAsyncKeyState (오타 수정: getAsyncKeyState, 그리고 호출 시 괄호 추가)
var getAsyncKeyState = Module.findExportByName("user32.dll","GetAsyncKeyState");
if (getAsyncKeyState) {
    Interceptor.attach(getAsyncKeyState, {
        onEnter: function(args){
            var vKey = args[0].toInt32();
            send({
                type:"GetKeyState",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                vKey: vKey,
                timestamp: getTimeStamp()
            });
        }
    });
}

// SetWindowsHookExA
var setWindowsHookExA = Module.findExportByName("user32.dll","SetWindowsHookExA");
if (setWindowsHookExA){
    Interceptor.attach(setWindowsHookExA, {
        onEnter: function(args){
            var idHook = args[0].toInt32();
            var lpfn = args[1];
            var hmod = args[2];
            var dwThreadId = args[3].toInt32();
            send({
                type:"SetWindowsHookExA",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                idHook: idHook,
                lpfn: lpfn,
                hmod: hmod,
                dwThreadId: dwThreadId,
                timestamp: getTimeStamp()
            });
        }
    });
}

// SetWindowsHookExW
var setWindowsHookExW = Module.findExportByName("user32.dll","SetWindowsHookExW");
if (setWindowsHookExW){
    Interceptor.attach(setWindowsHookExW, {
        onEnter: function(args){
            var idHook = args[0].toInt32();
            var lpfn = args[1];
            var hmod = args[2];
            var dwThreadId = args[3].toInt32();
            send({
                type:"SetWindowsHookExW",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                idHook: idHook,
                lpfn: lpfn,
                hmod: hmod,
                dwThreadId: dwThreadId,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ShellExecuteA
var shellExecuteA = Module.findExportByName("user32.dll","ShellExecuteA");
if (shellExecuteA) {
    Interceptor.attach(shellExecuteA, {
        onEnter: function(args){
            var hwnd = args[0];
            var lpOperation = Memory.readCString(args[1]);
            var lpFile = Memory.readCString(args[2]);
            var lpParameters = Memory.readCString(args[3]);
            var lpDirectory = Memory.readCString(args[4]);
            var nShowCmd = args[5].toInt32();
            send({
                type:"ShellExecuteA",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                hwnd: hwnd,
                lpOperation: lpOperation,
                lpFile: lpFile,
                lpParameters: lpParameters,
                lpDirectory: lpDirectory,
                nShowCmd: nShowCmd,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ShellExecuteW 
var shellExecuteW = Module.findExportByName("user32.dll","ShellExecuteW");
if (shellExecuteW) {
    Interceptor.attach(shellExecuteW, {
        onEnter: function(args){
            var hwnd = args[0];
            var lpOperation = Memory.readUtf16String(args[1]);
            var lpFile = Memory.readCString(args[2]); 
            var lpParameters = Memory.readUtf16String(args[3]);
            var lpDirectory = Memory.readUtf16String(args[4]);
            var nShowCmd = args[5].toInt32();
            send({
                type:"ShellExecuteW",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                hwnd: hwnd,
                lpOperation: lpOperation,
                lpFile: lpFile,
                lpParameters: lpParameters,
                lpDirectory: lpDirectory,
                nShowCmd: nShowCmd,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ws2_32.dll의 accept
var accept = Module.findExportByName("ws2_32.dll", "accept");
if (accept) {
    Interceptor.attach(accept, {
        onEnter: function(args) {
            var s = args[0].toInt32();
            var addr = args[1];
            var addrlen = args[2].readInt();
            send({
                type: "accept",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                s: s,
                addr: addr,
                addrlen: addrlen,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ws2_32.dll의 bind
var bind = Module.findExportByName("ws2_32.dll", "bind");
if (bind) {
    Interceptor.attach(bind, {
        onEnter: function(args) {
            var s = args[0].toInt32();
            var sockaddr = args[1];
            var ip = sockaddr.add(4).readU32();
            var port = sockaddr.add(2).readU16();
            var namelen = args[2].toUInt32();
            send({
                type: "bind",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                s: s,
                ip: ip,
                port: port,
                namelen: namelen,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ws2_32.dll의 connect
var connect = Module.findExportByName("ws2_32.dll", "connect");
if (connect) {
    Interceptor.attach(connect, {
        onEnter: function(args) {
            var s = args[0].toInt32();
            var sockaddr = args[1];
            var ip = sockaddr.add(4).readU32();
            var port = sockaddr.add(2).readU16();
            var namelen = args[2].toUInt32();
            send({
                type: "connect",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                s: s,
                ip: ip,
                port: port,
                namelen: namelen,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ws2_32.dll의 socket
var socket = Module.findExportByName("ws2_32.dll", "socket");
if (socket) {
    Interceptor.attach(socket, {
        onEnter: function(args) {
            var af = args[0].toInt32();
            var type = args[1].toInt32();
            var protocol = args[2].toInt32();
            send({
                type: "socket",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                af: af,
                type: type,
                protocol: protocol,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ws2_32.dll의 WSASocket
var WSASocket = Module.findExportByName("ws2_32.dll", "WSASocket");
if (WSASocket) {
    Interceptor.attach(WSASocket, {
        onEnter: function(args) {
            var af = args[0].toInt32();
            var type = args[1].toInt32();
            var protocol = args[2].toInt32();
            var lpProtocolInfo = args[3];
            var g = args[4].toUInt32();
            var dwFlags = args[5].toUInt32();
            send({
                type: "WSASocket",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                af: af,
                type: type,
                protocol: protocol,
                lpProtocolInfo: lpProtocolInfo,
                g: g,
                dwFlags: dwFlags,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ws2_32.dll의 WSAIoctl
var WSAIoctl = Module.findExportByName("ws2_32.dll", "WSAIoctl");
if (WSAIoctl) {
    Interceptor.attach(WSAIoctl, {
        onEnter: function(args) {
            var s = args[0].toInt32();
            var dwIoControlCode = args[1].toUInt32();
            var lpvInBuffer = args[2];
            var cbInBuffer = args[3].toUInt32();
            var lpvOutBuffer = args[4];
            var cbOutBuffer = args[5].toUInt32();
            var lpcbBytesReturned = args[6].readUInt32();
            var lpOverlapped = args[7];
            var lpCompletionRoutine = args[8];
            send({
                type: "WSAIoctl",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                s: s,
                dwIoControlCode: dwIoControlCode,
                lpvInBuffer: lpvInBuffer,
                cbInBuffer: cbInBuffer,
                lpvOutBuffer: lpvOutBuffer,
                cbOutBuffer: cbOutBuffer,
                lpcbBytesReturned: lpcbBytesReturned,
                lpOverlapped: lpOverlapped,
                lpCompletionRoutine: lpCompletionRoutine,
                timestamp: getTimeStamp()
            });
        }
    });
}

// psapi.dll의 EnumProcesses
var enumProcesses = Module.findExportByName("psapi.dll", "EnumProcesses");
if (enumProcesses) {
    Interceptor.attach(enumProcesses, {
        onEnter: function(args) {
            var pProcessIds = args[0];
            var cb = args[1].toInt32();
            var pBytesReturned = args[2];
            send({
                type: "EnumProcesses",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                pProcessIds: pProcessIds,
                cb: cb,
                pBytesReturned: pBytesReturned,
                timestamp: getTimeStamp()
            });
        }
    });
}

// psapi.dll의 EnumProcessModules
var enumProcessModules = Module.findExportByName("psapi.dll", "EnumProcessModules");
if (enumProcessModules) {
    Interceptor.attach(enumProcessModules, {
        onEnter: function(args) {
            var hProcess = args[0];
            var lphModule = args[1];
            var cb = args[2].toInt32();
            var lpcbNeeded = args[3];
            send({
                type: "EnumProcessModules",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                hProcess: hProcess,
                lphModule: lphModule,
                cb: cb,
                lpcbNeeded: lpcbNeeded,
                timestamp: getTimeStamp()
            });
        }
    });
}

// shell32.dll의 ShellExecuteExW
var shellExecuteEx = Module.findExportByName("shell32.dll", "ShellExecuteExW");
if (shellExecuteEx) {
    Interceptor.attach(shellExecuteEx, {
        onEnter: function(args) {
            var pExecInfo = args[0];
            send({
                type: "ShellExecuteEx",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                pExecInfo: pExecInfo,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ws2_32.dll의 send 
var ws2_send = Module.findExportByName("ws2_32.dll", "send");
if (ws2_send) {
    Interceptor.attach(ws2_send, {
        onEnter: function(args) {
            var s = args[0].toInt32();
            var buf = Memory.readUtf8String(args[1]);
            var len = args[2].toUInt32();
            var flags = args[3].toUInt32();
            send({
                type: "ws2_send",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                s: s,
                buf: buf,
                len: len,
                flags: flags,
                timestamp: getTimeStamp()
            });
        }
    });
}

// ws2_32.dll의 recv
var recv = Module.findExportByName("ws2_32.dll", "recv");
if (recv) {
    Interceptor.attach(recv, {
        onEnter: function(args) {
            var s = args[0].toInt32();
            var buf = args[1]; // 버퍼이므로 그대로 전달
            var len = args[2].toUInt32();
            var flags = args[3].toUInt32();
            send({
                type: "recv",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                s: s,
                buf: buf,
                len: len,
                flags: flags,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 InternetOpenA
var internetOpenA = Module.findExportByName("wininet.dll", "InternetOpenA");
if (internetOpenA) {
    Interceptor.attach(internetOpenA, {
        onEnter: function(args){
            var lpszAgent = Memory.readCString(args[0]);
            var dwAccessType = args[1].toInt32();
            var lpszProxy = Memory.readCString(args[2]);
            var lpszProxyBypass = Memory.readCString(args[3]);
            var dwFlags = args[4].toInt32();
            send({
                type:"InternetOpenA",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                lpszAgent: lpszAgent,
                dwAccessType: dwAccessType,
                lpszProxy: lpszProxy,
                lpszProxyBypass: lpszProxyBypass,
                dwFlags: dwFlags,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 InternetOpenW
var internetOpenW = Module.findExportByName("wininet.dll", "InternetOpenW");
if (internetOpenW) {
    Interceptor.attach(internetOpenW, {
        onEnter: function(args){
            var lpszAgent = Memory.readUtf16String(args[0]);
            var dwAccessType = args[1].toInt32();
            var lpszProxy = Memory.readUtf16String(args[2]);
            var lpszProxyBypass = Memory.readUtf16String(args[3]);
            var dwFlags = args[4].toInt32();
            send({
                type:"InternetOpenW",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                lpszAgent: lpszAgent,
                dwAccessType: dwAccessType,
                lpszProxy: lpszProxy,
                lpszProxyBypass: lpszProxyBypass,
                dwFlags: dwFlags,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 InternetOpenUrlA
var InternetOpenUrlA = Module.findExportByName("wininet.dll", "InternetOpenUrlA");
if (InternetOpenUrlA) {
    Interceptor.attach(InternetOpenUrlA, {
        onEnter: function(args) {
            var hInternet = args[0];
            var lpszUrl = Memory.readUtf8String(args[1]);
            var lpszHeaders = args[2].isNull() ? null : Memory.readUtf8String(args[2]);
            var dwHeadersLength = args[3].toUInt32();
            var dwFlags = args[4].toUInt32();
            var dwContext = args[5].toUInt32();
            send({
                type: "InternetOpenUrlA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hInternet: hInternet,
                lpszUrl: lpszUrl,
                lpszHeaders: lpszHeaders,
                dwHeadersLength: dwHeadersLength,
                dwFlags: dwFlags,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 InternetOpenUrlW
var InternetOpenUrlW = Module.findExportByName("wininet.dll", "InternetOpenUrlW");
if (InternetOpenUrlW) {
    Interceptor.attach(InternetOpenUrlW, {
        onEnter: function(args) {
            var hInternet = args[0];
            var lpszUrl = Memory.readUtf16String(args[1]);
            var lpszHeaders = args[2].isNull() ? null : Memory.readUtf16String(args[2]);
            var dwHeadersLength = args[3].toUInt32();
            var dwFlags = args[4].toUInt32();
            var dwContext = args[5].toUInt32();
            send({
                type: "InternetOpenUrlW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hInternet: hInternet,
                lpszUrl: lpszUrl,
                lpszHeaders: lpszHeaders,
                dwHeadersLength: dwHeadersLength,
                dwFlags: dwFlags,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 InternetReadFile
var internetReadFile = Module.findExportByName("wininet.dll", "InternetReadFile");
if (internetReadFile) {
    Interceptor.attach(internetReadFile, {
        onEnter: function(args) {
            var hFile = args[0];
            var lpBuffer = args[1];
            var dwNumberOfBytesToRead = args[2].toInt32();
            var lpdwNumberOfBytesRead = args[3].toInt32();
            send({
                type:"InternetReadFile",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                hFile: hFile,
                lpBuffer: lpBuffer,
                dwNumberOfBytesToRead: dwNumberOfBytesToRead,
                lpdwNumberOfBytesRead: lpdwNumberOfBytesRead,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 InternetWriteFile
var internetWriteFile = Module.findExportByName("wininet.dll", "InternetWriteFile");
if (internetWriteFile) {
    Interceptor.attach(internetWriteFile, {
        onEnter: function(args) {
            var hFile = args[0];
            var lpBuffer = args[1];
            var dwNumberOfBytesToWrite = args[2].toInt32();
            var lpdwNumberOfBytesWritten = args[3].toInt32();
            send({
                type:"InternetWriteFile",
                event:"called",
                thread_id: Process.getCurrentThreadId(),
                hFile: hFile,
                lpBuffer: lpBuffer,
                dwNumberOfBytesToWrite: dwNumberOfBytesToWrite,
                lpdwNumberOfBytesWritten: lpdwNumberOfBytesWritten,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 InternetConnectA
var internetConnectA = Module.findExportByName("wininet.dll", "InternetConnectA");
if (internetConnectA) {
    Interceptor.attach(internetConnectA, {
        onEnter: function(args) {
            var hInternet = args[0];
            var lpszServerName = Memory.readCString(args[1]);
            var nServerPort = args[2].toInt32();
            var lpszUsername = Memory.readCString(args[3]);
            var lpszPassword = Memory.readCString(args[4]);
            var dwService = args[5].toInt32();
            var dwFlags = args[6].toInt32();
            var dwContext = args[7].toInt32();
            send({
                type: "InternetConnectA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hInternet: hInternet,
                lpszServerName: lpszServerName,
                nServerPort: nServerPort,
                lpszUsername: lpszUsername,
                lpszPassword: lpszPassword,
                dwService: dwService,
                dwFlags: dwFlags,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 InternetConnectW
var internetConnectW = Module.findExportByName("wininet.dll", "InternetConnectW");
if (internetConnectW) {
    Interceptor.attach(internetConnectW, {
        onEnter: function(args) {
            var hInternet = args[0];
            var lpszServerName = Memory.readUtf16String(args[1]);
            var nServerPort = args[2].toInt32();
            var lpszUsername = Memory.readUtf16String(args[3]);
            var lpszPassword = Memory.readUtf16String(args[4]);
            var dwService = args[5].toInt32();
            var dwFlags = args[6].toInt32();
            var dwContext = args[7].toInt32();
            send({
                type: "InternetConnectW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hInternet: hInternet,
                lpszServerName: lpszServerName,
                nServerPort: nServerPort,
                lpszUsername: lpszUsername,
                lpszPassword: lpszPassword,
                dwService: dwService,
                dwFlags: dwFlags,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 HttpOpenRequestA
var httpOpenRequestA = Module.findExportByName("wininet.dll", "HttpOpenRequestA");
if (httpOpenRequestA) {
    Interceptor.attach(httpOpenRequestA, {
        onEnter: function(args) {
            var hConnect = args[0];
            var lpszVerb = Memory.readCString(args[1]);
            var lpszObjectName = Memory.readCString(args[2]);
            var lpszVersion = Memory.readCString(args[3]);
            var lpszReferrer = Memory.readCString(args[4]);
            var lplpszAcceptTypes = args[5];
            var dwFlags = args[6].toInt32();
            var dwContext = args[7].toInt32();
            send({
                type: "HttpOpenRequestA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hConnect: hConnect,
                lpszVerb: lpszVerb,
                lpszObjectName: lpszObjectName,
                lpszVersion: lpszVersion,
                lpszReferrer: lpszReferrer,
                lplpszAcceptTypes: lplpszAcceptTypes,
                dwFlags: dwFlags,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 HttpOpenRequestW
var httpOpenRequestW = Module.findExportByName("wininet.dll", "HttpOpenRequestW");
if (httpOpenRequestW) {
    Interceptor.attach(httpOpenRequestW, {
        onEnter: function(args) {
            var hConnect = args[0];
            var lpszVerb = Memory.readUtf16String(args[1]);
            var lpszObjectName = Memory.readUtf16String(args[2]);
            var lpszVersion = Memory.readUtf16String(args[3]);
            var lpszReferrer = Memory.readUtf16String(args[4]);
            var lplpszAcceptTypes = args[5];
            var dwFlags = args[6].toInt32();
            var dwContext = args[7].toInt32();
            send({
                type: "HttpOpenRequestW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hConnect: hConnect,
                lpszVerb: lpszVerb,
                lpszObjectName: lpszObjectName,
                lpszVersion: lpszVersion,
                lpszReferrer: lpszReferrer,
                lplpszAcceptTypes: lplpszAcceptTypes,
                dwFlags: dwFlags,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 HttpSendRequestA
var httpSendRequestA = Module.findExportByName("wininet.dll", "HttpSendRequestA");
if (httpSendRequestA) {
    Interceptor.attach(httpSendRequestA, {
        onEnter: function(args) {
            var hRequest = args[0];
            var lpszHeaders = Memory.readCString(args[1]);
            var dwHeadersLength = args[2].toInt32();
            var lpOptional = args[3];
            var dwOptionalLength = args[4].toInt32();
            send({
                type: "HttpSendRequestA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hRequest: hRequest,
                lpszHeaders: lpszHeaders,
                dwHeadersLength: dwHeadersLength,
                lpOptional: lpOptional,
                dwOptionalLength: dwOptionalLength,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 HttpSendRequestW
var httpSendRequestW = Module.findExportByName("wininet.dll", "HttpSendRequestW");
if (httpSendRequestW) {
    Interceptor.attach(httpSendRequestW, {
        onEnter: function(args) {
            var hRequest = args[0];
            var lpszHeaders = Memory.readUtf16String(args[1]);
            var dwHeadersLength = args[2].toInt32();
            var lpOptional = args[3];
            var dwOptionalLength = args[4].toInt32();
            send({
                type: "HttpSendRequestW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hRequest: hRequest,
                lpszHeaders: lpszHeaders,
                dwHeadersLength: dwHeadersLength,
                lpOptional: lpOptional,
                dwOptionalLength: dwOptionalLength,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 HttpSendRequestExA
var httpSendRequestExA = Module.findExportByName("wininet.dll", "HttpSendRequestExA");
if (httpSendRequestExA) {
    Interceptor.attach(httpSendRequestExA, {
        onEnter: function(args) {
            var hRequest = args[0];
            var lpBuffersIn = args[1];
            var lpBuffersOut = args[2];
            var dwFlags = args[3].toInt32();
            var dwContext = args[4].toInt32();
            send({
                type: "HttpSendRequestExA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hRequest: hRequest,
                lpBuffersIn: lpBuffersIn,
                lpBuffersOut: lpBuffersOut,
                dwFlags: dwFlags,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

// wininet.dll의 HttpSendRequestExW
var httpSendRequestExW = Module.findExportByName("wininet.dll", "HttpSendRequestExW");
if (httpSendRequestExW) {
    Interceptor.attach(httpSendRequestExW, {
        onEnter: function(args) {
            var hRequest = args[0];
            var lpBuffersIn = args[1];
            var lpBuffersOut = args[2];
            var dwFlags = args[3].toInt32();
            var dwContext = args[4].toInt32();
            send({
                type: "HttpSendRequestExW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hRequest: hRequest,
                lpBuffersIn: lpBuffersIn,
                lpBuffersOut: lpBuffersOut,
                dwFlags: dwFlags,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

// urlmon.dll의 URLDownloadToFileA
var urlDownloadToFileA = Module.findExportByName("urlmon.dll", "URLDownloadToFileA");
if (urlDownloadToFileA) {
    Interceptor.attach(urlDownloadToFileA, {
        onEnter: function(args) {
            var pCaller = args[0];
            var szURL = Memory.readCString(args[1]);
            var szFileName = Memory.readCString(args[2]);
            var dwReserved = args[3].toInt32();
            var lpfnCB = args[4];
            send({
                type: "URLDownloadToFileA",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                pCaller: pCaller,
                szURL: szURL,
                szFileName: szFileName,
                dwReserved: dwReserved,
                lpfnCB: lpfnCB,
                timestamp: getTimeStamp()
            });
        }
    });
}

// urlmon.dll의 URLDownloadToFileW
var urlDownloadToFileW = Module.findExportByName("urlmon.dll", "URLDownloadToFileW");
if (urlDownloadToFileW) {
    Interceptor.attach(urlDownloadToFileW, {
        onEnter: function(args) {
            var pCaller = args[0];
            var szURL = Memory.readUtf16String(args[1]);
            var szFileName = Memory.readUtf16String(args[2]);
            var dwReserved = args[3].toInt32();
            var lpfnCB = args[4];
            send({
                type: "URLDownloadToFileW",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                pCaller: pCaller,
                szURL: szURL,
                szFileName: szFileName,
                dwReserved: dwReserved,
                lpfnCB: lpfnCB,
                timestamp: getTimeStamp()
            });
        }
    });
}

// netapi32.dll의 NetScheduleJobAdd
var netScheduleJobAdd = Module.findExportByName("netapi32.dll", "NetScheduleJobAdd");
if (netScheduleJobAdd) {
    Interceptor.attach(netScheduleJobAdd, {
        onEnter: function(args) {
            var ServerName = Memory.readUtf16String(args[0]);
            var Buffer = args[1];
            send({
                type: "NetScheduleJobAdd",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                ServerName: ServerName,
                Buffer: Buffer,
                timestamp: getTimeStamp()
            });
        }
    });
}

// shell32.dll의 ShellExecuteExW
var shellExecuteEx = Module.findExportByName("shell32.dll", "ShellExecuteExW");
if (shellExecuteEx) {
    Interceptor.attach(shellExecuteEx, {
        onEnter: function(args) {
            var pExecInfo = args[0];
            send({
                type: "ShellExecuteEx",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                pExecInfo: pExecInfo,
                timestamp: getTimeStamp()
            });
        }
    });
}

// winhttp.dll의 WinHttpSendRequest
var winHttpSendRequest = Module.findExportByName("winhttp.dll", "WinHttpSendRequest");
if (winHttpSendRequest) {
    Interceptor.attach(winHttpSendRequest, {
        onEnter: function(args) {
            var hRequest = args[0];
            var pwszHeaders = Memory.readUtf16String(args[1]);
            var dwHeadersLength = args[2].toInt32();
            var lpOptional = args[3];
            var dwOptionalLength = args[4].toInt32();
            var dwTotalLength = args[5].toInt32();
            var dwContext = args[6].toInt32();
            send({
                type: "WinHttpSendRequest",
                event: "called",
                thread_id: Process.getCurrentThreadId(),
                hRequest: hRequest,
                pwszHeaders: pwszHeaders,
                dwHeadersLength: dwHeadersLength,
                lpOptional: lpOptional,
                dwOptionalLength: dwOptionalLength,
                dwTotalLength: dwTotalLength,
                dwContext: dwContext,
                timestamp: getTimeStamp()
            });
        }
    });
}

