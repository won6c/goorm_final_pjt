/*
    Frida Hook Script
    - 모든 모듈에 대해 export 함수를 후킹 시도합니다.
    - 단, kernel32.dll과 ntdll.dll의 경우에는 화이트리스트에 포함된 함수만 후킹합니다.
*/

// 이미 후킹한 함수의 주소를 기록하여 중복 후킹 방지
var hooked_functions = {};

// kernel32.dll에서 후킹할 함수 화이트리스트 (예시)
var whitelistKernel32 = [
    "CreateFileA",
    "CreateFileW",
    "WriteFile",
    "ReadFile",
    "LoadLibraryA",
    "LoadLibraryW",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "CreateProcessA",
    "CreateProcessW",
    "GetProcAddress",
    "IsDebuggerPresent"
];

// ntdll.dll에서 후킹할 함수 화이트리스트 (예시)
var whitelistNtdll = [
    "NtOpenProcess",
    "NtQueryInformationProcess",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtWriteVirtualMemory"
];

// 후킹할 함수를 attach하는 헬퍼 함수
function hook_function(moduleName, funcName, address) {
    try {
        var addrStr = address.toString();
        if (hooked_functions[addrStr])
            return;
        hooked_functions[addrStr] = true;
        
        Interceptor.attach(address, {
            onEnter: function(args) {
                var now = new Date();
                // 로그 메시지: [타임스탬프] 모듈이름!함수이름
                send("[" + now.toISOString() + "] " + moduleName + "!" + funcName);
            }
        });
    } catch (e) {
        // 후킹 실패한 경우 (필요 시 아래 로그를 활성화)
        send("Failed to hook " + moduleName + "!" + funcName);
    }
}

// 모듈 내의 export 함수들을 열거하며 후킹 (필터 적용)
function hook_module_exports(moduleName) {
    try {
        var exports = Module.enumerateExports(moduleName);
        send("Module : "+moduleName)
        exports.forEach(function(exp) {
            if (exp.type === "function") {
                // kernel32.dll: 화이트리스트에 포함된 함수만 후킹
                if (moduleName.toLowerCase() === "kernel32.dll") {
                    if (whitelistKernel32.indexOf(exp.name) !== -1) {
                        hook_function(moduleName, exp.name, exp.address);
                    }
                    else{
                        hook_function(moduleName, exp.name, exp.address);
                    }
                }
                // ntdll.dll: 화이트리스트에 포함된 함수만 후킹
                else if (moduleName.toLowerCase() === "ntdll.dll") {
                    if (whitelistNtdll.indexOf(exp.name) !== -1) {
                        hook_function(moduleName, exp.name, exp.address);
                    }
                    else{
                        //hook_function(moduleName, exp.name, exp.address);
                    }
                }
                else if (moduleName.toLowerCase()=== "msvcp_win.dll"){

                }
                // 그 외의 모듈은 모두 후킹
                else {
                    hook_function(moduleName, exp.name, exp.address);
                }
            }
        });
    } catch (e) {
        // 모듈 열거 실패 시 무시 (필요 시 아래 로그를 활성화)
        send("Failed to enumerate exports for " + moduleName + ": " + e);
    }
}

// 현재 로드된 모든 모듈에 대해 후킹 시도
function hook_all_modules() {
    var modules = Process.enumerateModules();
    modules.forEach(function(module) {
        hook_module_exports(module.name);
    });
}

// 최초 후킹 실행
hook_all_modules();

// 동적으로 새 모듈이 로드되는 경우를 위해 주기적으로 후킹 시도 (5초 주기)
//setInterval(function(){
//    hook_all_modules();
//}, 5000);
