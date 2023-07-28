using Serilog;
using Serilog.Templates;
using Serilog.Templates.Themes;

namespace PangyaSnifferCli;

public static class LogExtensions
{
    private static readonly ExpressionTemplate Format =
        new("[{@t:HH:mm:ss.fff} {@l:u3}] {@m}\n{@x}", theme: TemplateTheme.Literate);

    public static LoggerConfiguration ConfigureLogger(this LoggerConfiguration loggerConfiguration)
    {
        return loggerConfiguration
#if DEBUG
            .MinimumLevel.Debug()
#endif
            .Enrich.FromLogContext()
            .WriteTo.Console(Format)
            .WriteTo.File(Format, $"pl_{DateTime.UtcNow:dd-MM-yyyy_HH-mm-ss}.log");
    }
}