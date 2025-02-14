// CreateFileA 
var createFileA = Module.findExportByName("kernel32.dll", "CreateFileA");
if (createFileA) {
    Interceptor.attach(createFileA, {
        onEnter: function(args) {
            var fileNameA = Memory.readCString(args[0]);
            send({
                type: "CreateFileA",
                event: "called",
                fileName: fileNameA,
                timestamp: getTimestamp()
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
                fileName: fileNameW,
                timestamp: getTimestamp()
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
                bufferContent: content,
                timestamp: getTimestamp()
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
                bufferContent: content,
                timestamp: getTimestamp()
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
                fileName: fileNameA,
                timestamp: getTimestamp()
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
                fileName: fileNameW,
                timestamp: getTimestamp()
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
                timestamp: getTimestamp()
            });
        },
        onLeave: function(retval) {
            send({
                type: "CreateProcessA",
                event: "returned",
                retval: retval.toString(),
                timestamp: getTimestamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "CreateProcessA not found",
        timestamp: getTimestamp()
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
                timestamp: getTimestamp()
            });
        },
        onLeave: function(retval) {
            send({
                type: "CreateProcessAsUserA",
                event: "returned",
                retval: retval.toString(),
                timestamp: getTimestamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "CreateProcessAsUserA not found",
        timestamp: getTimestamp()
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
                timestamp: getTimestamp()
            });
        },
        onLeave: function(retval) {
            send({
                type: "CreateProcessAsUserW",
                event: "returned",
                retval: retval.toString(),
                timestamp: getTimestamp()
            });
        }
    });
} else {
    send({
        type: "error",
        message: "CreateProcessAsUserW not found",
        timestamp: getTimestamp()
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
                timestamp: getTimestamp()
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
                timestamp: getTimestamp()
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

// CreateRemoteThread
var createRemoteThread = Module.findExportByName("kernel32.dll", "CreateRemoteThread");
if (createRemoteThread) {
    Interceptor.attach(createRemoteThread, {
        onEnter: function(args) {
            this.startRoutine = args[3];
            this.param = args[4];
            send({
                type: "CreateRemoteThread",
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
                    type: "CreateRemoteThread",
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
        message: "CreateRemoteThread not found",
        timestamp: getTimestamp()
    });
}

// CreateRemoteThreadEx
var createRemoteThreadEx = Module.findExportByName("kernel32.dll", "CreateRemoteThreadEx");
if (createRemoteThreadEx) {
    Interceptor.attach(createRemoteThreadEx, {
        onEnter: function(args) {
            this.startRoutine = args[3];
            this.param = args[4];
            send({
                type: "CreateRemoteThreadEx",
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
                    type: "CreateRemoteThreadEx",
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
        message: "CreateRemoteThreadEx not found",
        timestamp: getTimestamp()
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

// GetModuleHandleA
var getModuleHandleA = Module.findExportByName("kernel32.dll", "GetModuleHandleA");
if (getModuleHandleA) {
    Interceptor.attach(getModuleHandleA, {
        onEnter: function(args) {
            var moduleName = Memory.readCString(args[0]);
            send({
                type: "GetModuleHandleA",
                event: "called",
                moduleName: moduleName,
                timestamp: getTimestamp()
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
                moduleName: moduleName,
                timestamp: getTimestamp()
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
                moduleName: moduleName,
                timestamp: getTimestamp()
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
                moduleName: moduleName,
                timestamp: getTimestamp()
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
                fileName: fileName,
                timestamp: getTimestamp()
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
                fileName: fileName,
                timestamp: getTimestamp()
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
                lpLibFileName: lib,
                timestamp: getTimestamp()
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
                lpLibFileName: lib,
                timestamp: getTimestamp()
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
                lpLibFileName: lib,
                Flags: flag,
                timestamp: getTimestamp()
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
                lpLibFileName: lib,
                Flags: flag,
                timestamp: getTimestamp()
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
                lpwLibFileName: lib,
                timestamp: getTimestamp()
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
            var api = Memory.readCString(args[1]);
            this.apiName = api; 
            send({
                type: "GetProcAddress",
                event: "called",
                module: moduleName,
                procName: api,
                timestamp: getTimestamp()
            });
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                var funcAddrStr = retval.toString();
                if (!hookedAPIs[funcAddrStr]) {
                    hookedAPIs[funcAddrStr] = true;
                    var capturedProcName = this.apiName || "unknown";
                    send({
                        type: "GetProcAddress",
                        event: "interceptor_attached",
                        procName: capturedProcName,
                        address: funcAddrStr,
                        timestamp: getTimestamp()
                    });
                    try {
                        Interceptor.attach(retval, {
                            onEnter: function(args) {
                                send({
                                    type: "API Intercept",
                                    event: "called",
                                    procName: capturedProcName,
                                    address: funcAddrStr,
                                    timestamp: getTimestamp()
                                });
                            }
                        });
                    } catch (e) {
                        send({
                            type: "error",
                            message: "Failed to attach interceptor to " + funcAddrStr,
                            timestamp: getTimestamp()
                        });
                    }
                }
            }
        }
    });
} else {
    send({
        type: "error",
        message: "GetProcAddress not found",
        timestamp: getTimestamp()
    });
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
                ServiceName: serviceName,
                DisplayName: displayName,
                ServiceType: serviceType,
                StartType: startType,
                lpBinaryPathName: binPath,
                lpDependencies: dependencies,
                lpServiceStartName: serviceStartName,
                lpPassword: pass,
                timestamp: getTimestamp()
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
                ServiceName: serviceName,
                DisplayName: displayName,
                ServiceType: serviceType,
                StartType: startType,
                lpBinaryPathName: binPath,
                lpDependencies: dependencies,
                lpServiceStartName: serviceStartName,
                lpPassword: pass,
                timestamp: getTimestamp()
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
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimestamp()
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
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimestamp()
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
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimestamp()
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
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimestamp()
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
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimestamp()
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
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimestamp()
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
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimestamp()
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
                hKey: hKey,
                lpSubKey: subKey,
                timestamp: getTimestamp()
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
                container: container,
                provider: provider,
                provType: provType,
                timestamp: getTimestamp()
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
                container: container,
                provider: provider,
                provType: provType,
                timestamp: getTimestamp()
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
                hKey: hKey,
                hHash: hHash,
                isFinal: isFinal,
                dwFlags: dwFlags,
                pbData: Memory.readByteArray(pbData, dwBufLen),
                pdwDataLen: Memory.readUInt(pdwDataLen),
                dwBufLen: dwBufLen,
                timestamp: getTimestamp()
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
                hKey: hKey,
                hHash: hHash,
                isFinal: isFinal,
                dwFlags: dwFlags,
                pbData: Memory.readByteArray(pbData, dataLen),
                pdwDataLen: dataLen,
                timestamp: getTimestamp()
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
                Algid: alg_id,
                hKey: hKey,
                timestamp: getTimestamp()
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
                pbData: pbData,
                timestamp: getTimestamp()
            });
        }
    });
}
