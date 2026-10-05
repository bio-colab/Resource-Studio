using System.IO;
using System.Windows;

namespace ResourceStudio.Windows;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "startup_error.txt"), args.ExceptionObject.ToString());
        };
        DispatcherUnhandledException += (s, args) =>
        {
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "startup_error.txt"), args.Exception.ToString());
        };
        base.OnStartup(e);
    }
}
