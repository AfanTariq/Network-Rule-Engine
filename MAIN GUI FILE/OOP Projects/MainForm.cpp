#include "MainForm.h"


using namespace System;
using namespace System::Windows::Forms;

[STAThreadAttribute]

int main(array<String^>^ args)
{
    Application::EnableVisualStyles();
    Application::SetCompatibleTextRenderingDefault(false);

    myproject::MainForm^ form = gcnew myproject::MainForm();
    Application::Run(form);

    return 0;
}
