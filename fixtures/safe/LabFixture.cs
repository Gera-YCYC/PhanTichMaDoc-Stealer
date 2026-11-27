// Inert managed fixture: no IO, network, credentials, execution or entry point.
// Suspicious-looking strings are test DATA, not an implemented stealer.
public static class LabFixture
{
    public static string[] Describe()
    {
        return new string[] {
            "SAFE_LAB_FIXTURE",
            "https://fixture.invalid/documentation",
            "Login Data is a documentation example, not accessed here.",
            "No network request or credential access is implemented."
        };
    }
}
