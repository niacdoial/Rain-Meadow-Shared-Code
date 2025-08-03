using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
//using Newtonsoft.Json;

namespace RainMeadow.Shared
{
    public partial class SharedCodeLogger
    {
        public static void Debug(object data, [CallerFilePath] string callerFile = "", [CallerMemberName] string callerName = "")
        {
            DebugInner.Invoke(data, callerFile, callerName);
        }
        public static void DebugMe([CallerFilePath] string callerFile = "", [CallerMemberName] string callerName = "")
        {
            DebugMeInner.Invoke(callerFile, callerName);
        }
        public static void Error(object data, [CallerFilePath] string callerFile = "", [CallerMemberName] string callerName = "")
        {
            ErrorInner.Invoke(data, callerFile, callerName);
        }

        public delegate void Logger_t(object data , string filename, string method);
        public delegate void DebugMe_t(string filename, string method);
        public static event Logger_t ErrorInner = delegate { };
        public static event Logger_t DebugInner = delegate { };
        public static event DebugMe_t DebugMeInner = delegate { };

        // [Conditional("TRACING")]
        // public static void Stacktrace()
        // {
        //     var stacktrace = Environment.StackTrace;
        //     stacktrace = stacktrace.Substring(stacktrace.IndexOf('\n') + 1);
        //     stacktrace = stacktrace.Substring(stacktrace.IndexOf('\n'));
        //     instance.Logger.LogInfo(stacktrace);
        // }

        // [Conditional("TRACING")]
        // public static void Dump(object data, [CallerFilePath] string callerFile = "", [CallerMemberName] string callerName = "")
        // {
        //     var dump = JsonConvert.SerializeObject(data, Formatting.Indented, new JsonSerializerSettings
        //     {
        //         ContractResolver = ShallowJsonDump.customResolver,
        //         Converters = new List<JsonConverter>() { new ShallowJsonDump() }

        //     });
        //     instance.Logger.LogInfo($"{LogDOT()}|{LogTime()}|{TrimCaller(callerFile)}.{callerName}:{dump}");
        // }

        // // tracing stays on for one net-frame after pressing L
        // public static bool tracing;
        // // this better captures the caller member info for delegates/lambdas at the cost of using the stackframe
        // [Conditional("TRACING")]
        // public static void Trace(object data, [CallerFilePath] string callerFile = "")
        // {
        //     if (tracing)
        //     {
        //     instance.Logger.LogInfo($"{LogDOT()}|{LogTime()}|{TrimCaller(callerFile)}.{new StackFrame(1, false).GetMethod()}:{data}");
        //     }
        // }
    }
}
