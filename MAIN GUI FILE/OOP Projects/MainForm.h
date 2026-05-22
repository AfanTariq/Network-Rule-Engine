#pragma once
#include "Class.h"
#include "BasicFileEncryptor.h"
#include "IRuleConflictResolver.h"
#include "NetworkPacketCapture.h"
#include "Packet.h"
#include "priorityConflictResolver.h"
#include "Rule.h"
#include "RuleEngine.h"
#include "TimeBasedRule.h"
#include "TrafficLogger.h"
#include"resource.h"
#include<sstream>
#include <msclr/marshal_cppstd.h>
#include <map>
#include <set>
#include <msclr/marshal.h>
#include <msclr/marshal.h>

using namespace Microsoft::VisualBasic;
class ruleengine;

namespace myproject {

    using namespace System;
    using namespace System::ComponentModel;
    using namespace System::Collections;
    using namespace System::Windows::Forms;
    using namespace System::Data;
    using namespace System::Drawing;
    using namespace System::Threading;


    public ref class MainForm : public System::Windows::Forms::Form
    {
    private:
        RuleEngine* engine;
        NetworkPacketCapture* packetCapture;
        bool isCapturing;
    private: System::Windows::Forms::DataGridView^ dgvDefaultRules;
           Thread^ captureThread;

    public:
        MainForm(void)
        {
            InitializeComponent();
            isCapturing = false;
            engine = new RuleEngine(ActionType::DENY, "engine_traffic_gui.log");
            packetCapture = new NetworkPacketCapture("");
            InitializeDefaultRules();
        }

        ~MainForm()
        {
            if (isCapturing) StopCapture();
            delete engine;
            delete packetCapture;
            if (components)
            {
                delete components;
            }
        }

    private:
        // Add these as private members in MainForm:
        System::Windows::Forms::Label^ lblDefaultRules;
        System::Windows::Forms::Label^ lblFileRules;

        System::Windows::Forms::DataGridView^ dgvFileRules;


        // Form controls
        System::Windows::Forms::TabControl^ tabControl;
        System::Windows::Forms::TabPage^ tabRules;
        System::Windows::Forms::TabPage^ tabCapture;
        System::Windows::Forms::TabPage^ tabAnalysis;
        System::Windows::Forms::TabPage^ tabLogs;

        // Rules tab controls
        System::Windows::Forms::DataGridView^ rulesGridView;
        System::Windows::Forms::Button^ btnAddRule;
        System::Windows::Forms::Button^ btnRemoveRule;
        System::Windows::Forms::Button^ btnSaveRules;
        System::Windows::Forms::Button^ btnLoadRules;

        // Capture tab controls
        System::Windows::Forms::ComboBox^ cmbNetworkDevices;
        System::Windows::Forms::Button^ btnRefreshDevices;
        System::Windows::Forms::Button^ btnStartCapture;
        System::Windows::Forms::Button^ btnStopCapture;
        System::Windows::Forms::NumericUpDown^ numPacketsToCapture;
        System::Windows::Forms::RichTextBox^ rtbCaptureLog;
        System::Windows::Forms::CheckBox^ chkEncryptLogs;
        System::Windows::Forms::TextBox^ txtEncryptionKey;


        // Analysis tab controls
        System::Windows::Forms::Button^ btnBrowsePacketFile;
        System::Windows::Forms::TextBox^ txtPacketFilePath;
        System::Windows::Forms::Button^ btnAnalyzeFile;
        System::Windows::Forms::RichTextBox^ rtbAnalysisResults;

        // Logs tab controls
        System::Windows::Forms::RichTextBox^ rtbSystemLog;
        System::Windows::Forms::Button^ btnClearLogs;
        System::Windows::Forms::Button^ btnSaveLogs;

        System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
        void InitializeComponent(void)
        {
            this->tabControl = (gcnew System::Windows::Forms::TabControl());
            this->tabRules = (gcnew System::Windows::Forms::TabPage());
            this->lblDefaultRules = (gcnew System::Windows::Forms::Label());
            this->lblFileRules = (gcnew System::Windows::Forms::Label());
            this->dgvFileRules = (gcnew System::Windows::Forms::DataGridView());
            this->rulesGridView = (gcnew System::Windows::Forms::DataGridView());
            this->btnAddRule = (gcnew System::Windows::Forms::Button());
            this->btnRemoveRule = (gcnew System::Windows::Forms::Button());
            this->btnSaveRules = (gcnew System::Windows::Forms::Button());
            this->btnLoadRules = (gcnew System::Windows::Forms::Button());
            this->tabCapture = (gcnew System::Windows::Forms::TabPage());
            this->cmbNetworkDevices = (gcnew System::Windows::Forms::ComboBox());
            this->btnRefreshDevices = (gcnew System::Windows::Forms::Button());
            this->btnStartCapture = (gcnew System::Windows::Forms::Button());
            this->btnStopCapture = (gcnew System::Windows::Forms::Button());
            this->numPacketsToCapture = (gcnew System::Windows::Forms::NumericUpDown());
            this->rtbCaptureLog = (gcnew System::Windows::Forms::RichTextBox());
            this->chkEncryptLogs = (gcnew System::Windows::Forms::CheckBox());
            this->txtEncryptionKey = (gcnew System::Windows::Forms::TextBox());
            this->tabAnalysis = (gcnew System::Windows::Forms::TabPage());
            this->btnBrowsePacketFile = (gcnew System::Windows::Forms::Button());
            this->txtPacketFilePath = (gcnew System::Windows::Forms::TextBox());
            this->btnAnalyzeFile = (gcnew System::Windows::Forms::Button());
            this->rtbAnalysisResults = (gcnew System::Windows::Forms::RichTextBox());
            this->tabLogs = (gcnew System::Windows::Forms::TabPage());
            this->rtbSystemLog = (gcnew System::Windows::Forms::RichTextBox());
            this->btnClearLogs = (gcnew System::Windows::Forms::Button());
            this->btnSaveLogs = (gcnew System::Windows::Forms::Button());
            this->dgvDefaultRules = (gcnew System::Windows::Forms::DataGridView());
            this->tabControl->SuspendLayout();
            this->tabRules->SuspendLayout();
            (cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->dgvFileRules))->BeginInit();
            (cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->rulesGridView))->BeginInit();
            this->tabCapture->SuspendLayout();
            (cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->numPacketsToCapture))->BeginInit();
            this->tabAnalysis->SuspendLayout();
            this->tabLogs->SuspendLayout();
            (cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->dgvDefaultRules))->BeginInit();
            this->SuspendLayout();
            // 
            // tabControl
            // 
            this->tabControl->Controls->Add(this->tabRules);
            this->tabControl->Controls->Add(this->tabCapture);
            this->tabControl->Controls->Add(this->tabAnalysis);
            this->tabControl->Controls->Add(this->tabLogs);
            this->tabControl->Dock = System::Windows::Forms::DockStyle::Fill;
            this->tabControl->Location = System::Drawing::Point(0, 0);
            this->tabControl->Name = L"tabControl";
            this->tabControl->SelectedIndex = 0;
            this->tabControl->Size = System::Drawing::Size(800, 600);
            this->tabControl->TabIndex = 0;
            // 
            // tabRules
            // 
            this->tabRules->Controls->Add(this->lblDefaultRules);
            this->tabRules->Controls->Add(this->dgvDefaultRules);
            this->tabRules->Controls->Add(this->lblFileRules);
            this->tabRules->Controls->Add(this->dgvFileRules);
            //this->tabRules->Controls->Add(this->rulesGridView);
            this->tabRules->Controls->Add(this->btnAddRule);
            this->tabRules->Controls->Add(this->btnRemoveRule);
            this->tabRules->Controls->Add(this->btnSaveRules);
            this->tabRules->Controls->Add(this->btnLoadRules);
            this->tabRules->Location = System::Drawing::Point(4, 22);
            this->tabRules->Name = L"tabRules";
            this->tabRules->Padding = System::Windows::Forms::Padding(3);
            this->tabRules->Size = System::Drawing::Size(792, 574);
            this->tabRules->TabIndex = 0;
            this->tabRules->Text = L"Rules Management";
            this->tabRules->UseVisualStyleBackColor = true;
            // 
            // lblDefaultRules
            // 
            this->lblDefaultRules->AutoSize = true;
            this->lblDefaultRules->Location = System::Drawing::Point(6, 6);
            this->lblDefaultRules->Name = L"lblDefaultRules";
            this->lblDefaultRules->Size = System::Drawing::Size(108, 13);
            this->lblDefaultRules->TabIndex = 0;
            this->lblDefaultRules->Text = L"System Default Rules";
            // 
            // lblFileRules
            // 
            this->lblFileRules->AutoSize = true;
            this->lblFileRules->Location = System::Drawing::Point(6, 236);
            this->lblFileRules->Name = L"lblFileRules";
            this->lblFileRules->Size = System::Drawing::Size(79, 13);
            this->lblFileRules->TabIndex = 2;
            this->lblFileRules->Text = L"Rules From File";
            // 
            // 
            // dgvFileRules
            // 
            
            this->dgvFileRules->Anchor = static_cast<System::Windows::Forms::AnchorStyles>(
                System::Windows::Forms::AnchorStyles::Top |
                System::Windows::Forms::AnchorStyles::Bottom |
                System::Windows::Forms::AnchorStyles::Left |
                System::Windows::Forms::AnchorStyles::Right);
            this->dgvFileRules->Location = System::Drawing::Point(6, 256);
            this->dgvFileRules->Name = L"dgvFileRules";
            this->dgvFileRules->Size = System::Drawing::Size(780, 250);
            this->dgvFileRules->TabIndex = 3;
            
            // btnAddRule
            // 
            this->btnAddRule->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Left));
            this->btnAddRule->Location = System::Drawing::Point(6, 512);
            this->btnAddRule->Name = L"btnAddRule";
            this->btnAddRule->Size = System::Drawing::Size(100, 30);
            this->btnAddRule->TabIndex = 1;
            this->btnAddRule->Text = L"Add Rule";
            this->btnAddRule->UseVisualStyleBackColor = true;
            this->btnAddRule->Click += gcnew System::EventHandler(this, &MainForm::btnAddRule_Click);
            // 
            // btnRemoveRule
            // 
            this->btnRemoveRule->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Left));
            this->btnRemoveRule->Location = System::Drawing::Point(112, 512);
            this->btnRemoveRule->Name = L"btnRemoveRule";
            this->btnRemoveRule->Size = System::Drawing::Size(100, 30);
            this->btnRemoveRule->TabIndex = 2;
            this->btnRemoveRule->Text = L"Remove Rule";
            this->btnRemoveRule->UseVisualStyleBackColor = true;
            this->btnRemoveRule->Click += gcnew System::EventHandler(this, &MainForm::btnRemoveRule_Click);
            // 
            // btnSaveRules
            // 
            this->btnSaveRules->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Right));
            this->btnSaveRules->Location = System::Drawing::Point(580, 512);
            this->btnSaveRules->Name = L"btnSaveRules";
            this->btnSaveRules->Size = System::Drawing::Size(100, 30);
            this->btnSaveRules->TabIndex = 3;
            this->btnSaveRules->Text = L"Save Rules";
            this->btnSaveRules->UseVisualStyleBackColor = true;
            this->btnSaveRules->Click += gcnew System::EventHandler(this, &MainForm::btnSaveRules_Click);
            // 
            // btnLoadRules
            // 
            this->btnLoadRules->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Right));
            this->btnLoadRules->Location = System::Drawing::Point(686, 512);
            this->btnLoadRules->Name = L"btnLoadRules";
            this->btnLoadRules->Size = System::Drawing::Size(100, 30);
            this->btnLoadRules->TabIndex = 4;
            this->btnLoadRules->Text = L"Load Rules";
            this->btnLoadRules->UseVisualStyleBackColor = true;
            this->btnLoadRules->Click += gcnew System::EventHandler(this, &MainForm::btnLoadRules_Click);
            // 
            // tabCapture
            // 
            this->tabCapture->Controls->Add(this->cmbNetworkDevices);
            this->tabCapture->Controls->Add(this->btnRefreshDevices);
            this->tabCapture->Controls->Add(this->btnStartCapture);
            this->tabCapture->Controls->Add(this->btnStopCapture);
            this->tabCapture->Controls->Add(this->numPacketsToCapture);
            this->tabCapture->Controls->Add(this->rtbCaptureLog);
            this->tabCapture->Controls->Add(this->chkEncryptLogs);
            this->tabCapture->Controls->Add(this->txtEncryptionKey);
            this->tabCapture->Location = System::Drawing::Point(4, 22);
            this->tabCapture->Name = L"tabCapture";
            this->tabCapture->Padding = System::Windows::Forms::Padding(3);
            this->tabCapture->Size = System::Drawing::Size(792, 574);
            this->tabCapture->TabIndex = 1;
            this->tabCapture->Text = L"Packet Capture";
            this->tabCapture->UseVisualStyleBackColor = true;
            // 
            // cmbNetworkDevices
            // 
            this->cmbNetworkDevices->Anchor = static_cast<System::Windows::Forms::AnchorStyles>(((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Left)
                | System::Windows::Forms::AnchorStyles::Right));
            this->cmbNetworkDevices->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.75F));
            this->cmbNetworkDevices->FormattingEnabled = true;
            this->cmbNetworkDevices->Location = System::Drawing::Point(6, 6);
            this->cmbNetworkDevices->Name = L"cmbNetworkDevices";
            this->cmbNetworkDevices->Size = System::Drawing::Size(600, 23);
            this->cmbNetworkDevices->TabIndex = 0;
            // 
            // btnRefreshDevices
            // 
            this->btnRefreshDevices->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Right));
            this->btnRefreshDevices->Location = System::Drawing::Point(612, 6);
            this->btnRefreshDevices->Name = L"btnRefreshDevices";
            this->btnRefreshDevices->Size = System::Drawing::Size(174, 23);
            this->btnRefreshDevices->TabIndex = 1;
            this->btnRefreshDevices->Text = L"Refresh Network Devices";
            this->btnRefreshDevices->UseVisualStyleBackColor = true;
            this->btnRefreshDevices->Click += gcnew System::EventHandler(this, &MainForm::btnRefreshDevices_Click);
            // 
            // btnStartCapture
            // 
            this->btnStartCapture->Location = System::Drawing::Point(6, 33);
            this->btnStartCapture->Name = L"btnStartCapture";
            this->btnStartCapture->Size = System::Drawing::Size(100, 30);
            this->btnStartCapture->TabIndex = 2;
            this->btnStartCapture->Text = L"Start Capture";
            this->btnStartCapture->UseVisualStyleBackColor = true;
            this->btnStartCapture->Click += gcnew System::EventHandler(this, &MainForm::btnStartCapture_Click);
            // 
            // btnStopCapture
            // 
            this->btnStopCapture->Enabled = false;
            this->btnStopCapture->Location = System::Drawing::Point(112, 33);
            this->btnStopCapture->Name = L"btnStopCapture";
            this->btnStopCapture->Size = System::Drawing::Size(100, 30);
            this->btnStopCapture->TabIndex = 3;
            this->btnStopCapture->Text = L"Stop Capture";
            this->btnStopCapture->UseVisualStyleBackColor = true;
            this->btnStopCapture->Click += gcnew System::EventHandler(this, &MainForm::btnStopCapture_Click);
            // 
            // numPacketsToCapture
            // 
            this->numPacketsToCapture->Location = System::Drawing::Point(218, 38);
            this->numPacketsToCapture->Maximum = System::Decimal(gcnew cli::array< System::Int32 >(4) { 1000, 0, 0, 0 });
            this->numPacketsToCapture->Minimum = System::Decimal(gcnew cli::array< System::Int32 >(4) { 1, 0, 0, 0 });
            this->numPacketsToCapture->Name = L"numPacketsToCapture";
            this->numPacketsToCapture->Size = System::Drawing::Size(120, 20);
            this->numPacketsToCapture->TabIndex = 4;
            this->numPacketsToCapture->Value = System::Decimal(gcnew cli::array< System::Int32 >(4) { 10, 0, 0, 0 });
            // 
            // rtbCaptureLog
            // 
            this->rtbCaptureLog->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
                | System::Windows::Forms::AnchorStyles::Left)
                | System::Windows::Forms::AnchorStyles::Right));
            this->rtbCaptureLog->Location = System::Drawing::Point(6, 69);
            this->rtbCaptureLog->Name = L"rtbCaptureLog";
            this->rtbCaptureLog->ReadOnly = true;
            this->rtbCaptureLog->Size = System::Drawing::Size(780, 450);
            this->rtbCaptureLog->TabIndex = 5;
            this->rtbCaptureLog->Text = L"";
            // 
            // chkEncryptLogs
            // 
            this->chkEncryptLogs->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Left));
            this->chkEncryptLogs->AutoSize = true;
            this->chkEncryptLogs->Location = System::Drawing::Point(6, 525);
            this->chkEncryptLogs->Name = L"chkEncryptLogs";
            this->chkEncryptLogs->Size = System::Drawing::Size(88, 17);
            this->chkEncryptLogs->TabIndex = 6;
            this->chkEncryptLogs->Text = L"Encrypt Logs";
            this->chkEncryptLogs->UseVisualStyleBackColor = true;
            this->chkEncryptLogs->CheckedChanged += gcnew System::EventHandler(this, &MainForm::chkEncryptLogs_CheckedChanged);
            // 
            // txtEncryptionKey
            // 
            this->txtEncryptionKey->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Left));
            this->txtEncryptionKey->Enabled = false;
            this->txtEncryptionKey->Location = System::Drawing::Point(98, 525);
            this->txtEncryptionKey->Name = L"txtEncryptionKey";
            this->txtEncryptionKey->Size = System::Drawing::Size(200, 20);
            this->txtEncryptionKey->TabIndex = 7;
            this->txtEncryptionKey->Text = L"mySecretKey123";
            // 
            // tabAnalysis
            // 
            this->tabAnalysis->Controls->Add(this->btnBrowsePacketFile);
            this->tabAnalysis->Controls->Add(this->txtPacketFilePath);
            this->tabAnalysis->Controls->Add(this->btnAnalyzeFile);
            this->tabAnalysis->Controls->Add(this->rtbAnalysisResults);
            this->tabAnalysis->Location = System::Drawing::Point(4, 22);
            this->tabAnalysis->Name = L"tabAnalysis";
            this->tabAnalysis->Size = System::Drawing::Size(792, 574);
            this->tabAnalysis->TabIndex = 2;
            this->tabAnalysis->Text = L"Packet Analysis";
            this->tabAnalysis->UseVisualStyleBackColor = true;
            // 
            // btnBrowsePacketFile
            // 
            this->btnBrowsePacketFile->Location = System::Drawing::Point(6, 6);
            this->btnBrowsePacketFile->Name = L"btnBrowsePacketFile";
            this->btnBrowsePacketFile->Size = System::Drawing::Size(100, 23);
            this->btnBrowsePacketFile->TabIndex = 0;
            this->btnBrowsePacketFile->Text = L"Browse...";
            this->btnBrowsePacketFile->UseVisualStyleBackColor = true;
            this->btnBrowsePacketFile->Click += gcnew System::EventHandler(this, &MainForm::btnBrowsePacketFile_Click);
            // 
            // txtPacketFilePath
            // 
            this->txtPacketFilePath->Anchor = static_cast<System::Windows::Forms::AnchorStyles>(((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Left)
                | System::Windows::Forms::AnchorStyles::Right));
            this->txtPacketFilePath->Location = System::Drawing::Point(112, 8);
            this->txtPacketFilePath->Name = L"txtPacketFilePath";
            this->txtPacketFilePath->Size = System::Drawing::Size(580, 20);
            this->txtPacketFilePath->TabIndex = 1;
            // 
            // btnAnalyzeFile
            // 
            this->btnAnalyzeFile->Location = System::Drawing::Point(6, 35);
            this->btnAnalyzeFile->Name = L"btnAnalyzeFile";
            this->btnAnalyzeFile->Size = System::Drawing::Size(100, 23);
            this->btnAnalyzeFile->TabIndex = 2;
            this->btnAnalyzeFile->Text = L"Analyze File";
            this->btnAnalyzeFile->UseVisualStyleBackColor = true;
            this->btnAnalyzeFile->Click += gcnew System::EventHandler(this, &MainForm::btnAnalyzeFile_Click);
            // 
            // rtbAnalysisResults
            // 

            this->rtbAnalysisResults->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
                | System::Windows::Forms::AnchorStyles::Left)
                | System::Windows::Forms::AnchorStyles::Right));
            this->rtbAnalysisResults->Location = System::Drawing::Point(6, 64);
            this->rtbAnalysisResults->Name = L"rtbAnalysisResults";
            this->rtbAnalysisResults->ReadOnly = true;
            this->rtbAnalysisResults->Size = System::Drawing::Size(780, 500);
            this->rtbAnalysisResults->TabIndex = 3;
            this->rtbAnalysisResults->Text = L"";
            // 
            // tabLogs
            // 
            this->tabLogs->Controls->Add(this->rtbSystemLog);
            this->tabLogs->Controls->Add(this->btnClearLogs);
            this->tabLogs->Controls->Add(this->btnSaveLogs);
            this->tabLogs->Location = System::Drawing::Point(4, 22);
            this->tabLogs->Name = L"tabLogs";
            this->tabLogs->Size = System::Drawing::Size(792, 574);
            this->tabLogs->TabIndex = 3;
            this->tabLogs->Text = L"System Logs";
            this->tabLogs->UseVisualStyleBackColor = true;
            // 
            // rtbSystemLog
            // 
            this->rtbSystemLog->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
                | System::Windows::Forms::AnchorStyles::Left)
                | System::Windows::Forms::AnchorStyles::Right));
            this->rtbSystemLog->Location = System::Drawing::Point(6, 6);
            this->rtbSystemLog->Name = L"rtbSystemLog";
            this->rtbSystemLog->ReadOnly = true;
            this->rtbSystemLog->Size = System::Drawing::Size(780, 530);
            this->rtbSystemLog->TabIndex = 0;
            this->rtbSystemLog->Text = L"";
            // 
            // btnClearLogs
            // 
            this->btnClearLogs->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Left));
            this->btnClearLogs->Location = System::Drawing::Point(6, 542);
            this->btnClearLogs->Name = L"btnClearLogs";
            this->btnClearLogs->Size = System::Drawing::Size(100, 30);
            this->btnClearLogs->TabIndex = 1;
            this->btnClearLogs->Text = L"Clear Logs";
            this->btnClearLogs->UseVisualStyleBackColor = true;
            this->btnClearLogs->Click += gcnew System::EventHandler(this, &MainForm::btnClearLogs_Click);
            // 
            // btnSaveLogs
            // 
            this->btnSaveLogs->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Right));
            this->btnSaveLogs->Location = System::Drawing::Point(686, 542);
            this->btnSaveLogs->Name = L"btnSaveLogs";
            this->btnSaveLogs->Size = System::Drawing::Size(100, 30);
            this->btnSaveLogs->TabIndex = 2;
            this->btnSaveLogs->Text = L"Save Logs";
            this->btnSaveLogs->UseVisualStyleBackColor = true;
            this->btnSaveLogs->Click += gcnew System::EventHandler(this, &MainForm::btnSaveLogs_Click);
            // 
            // dgvDefaultRules
            // 
            this->dgvDefaultRules->Dock = System::Windows::Forms::DockStyle::Top; // or Fill if you want it to fill the area

            this->dgvDefaultRules->AllowUserToAddRows = false;
            this->dgvDefaultRules->AllowUserToDeleteRows = false;
            this->dgvDefaultRules->Location = System::Drawing::Point(6, 26);
            this->dgvDefaultRules->Name = L"dgvDefaultRules";
            this->dgvDefaultRules->ReadOnly = true;
            this->dgvDefaultRules->Size = System::Drawing::Size(780, 225);
            this->dgvDefaultRules->TabIndex = 1;
            // 
            // MainForm
            // 
            this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
            this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
            this->ClientSize = System::Drawing::Size(800, 600);
            this->Controls->Add(this->tabControl);
            this->Name = L"MainForm";
            this->Text = L"Network Rule Engine";
            this->Load += gcnew System::EventHandler(this, &MainForm::MainForm_Load);
            this->tabControl->ResumeLayout(false);
            this->tabRules->ResumeLayout(false);
            this->tabRules->PerformLayout();
            (cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->dgvFileRules))->EndInit();
           // (cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->rulesGridView))->EndInit();
            this->tabCapture->ResumeLayout(false);
            this->tabCapture->PerformLayout();
            (cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->numPacketsToCapture))->EndInit();
            this->tabAnalysis->ResumeLayout(false);
            this->tabAnalysis->PerformLayout();
            this->tabLogs->ResumeLayout(false);
            (cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->dgvDefaultRules))->EndInit();
            this->ResumeLayout(false);

        }
#pragma endregion

    private:
        // Initialize default rules (from your main.cpp)
        void InitializeDefaultRules()
        {
            engine->addRule(std::make_unique<::Rule>(engine->getNextAvailableId(), "Allow Corp Web HTTPS", "ANY", "10.0.1.0/24", -1, 443, "TCP", ActionType::ALLOW, 50));
            engine->addRule(std::make_unique<::Rule>(engine->getNextAvailableId(), "Allow Corp Web HTTP", "ANY", "10.0.1.0/24", -1, 80, "TCP", ActionType::ALLOW, 40));
            engine->addRule(std::make_unique<TimeBasedRule>(engine->getNextAvailableId(), "Allow FTP (Work Hours)", "ANY", "ANY", -1, 62774, "TCP", ActionType::ALLOW, 30, 9, 23));
            engine->addRule(std::make_unique<::Rule>(engine->getNextAvailableId(), "Block Bad Site", "ANY", "6.6.6.6", -1, -1, "ANY", ActionType::DENY, 100));
            engine->addRule(std::make_unique<::Rule>(engine->getNextAvailableId(), "Override Block Bad Site", "ANY", "6.6.6.6", -1, -1, "ANY", ActionType::ALLOW, 110));
            engine->addRule(std::make_unique<::Rule>(engine->getNextAvailableId(), "Log All Web to Corp", "ANY", "10.0.1.0/24", -1, 443, "TCP", ActionType::LOG, 45));
            engine->addRule(std::make_unique<::Rule>(engine->getNextAvailableId(), "Allow Local DNS", "ANY", "ANY", -1, 53, "UDP", ActionType::ALLOW, 60));
            engine->addRule(std::make_unique<::Rule>(engine->getNextAvailableId(), "Allow Local DNS", "ANY", "ANY", -1, 53, "TCP", ActionType::ALLOW, 60));
            engine->addRule(std::make_unique<::Rule>(engine->getNextAvailableId(), "Allow DHCP", "ANY", "ANY", 68, 67, "UDP", ActionType::ALLOW, 70));

            RefreshDefaultRulesGrid();
            LogMessage("Default rules initialized");
        }

        // Refresh the rules grid with current rules
        void RefreshDefaultRulesGrid()
        {
            dgvDefaultRules->Rows->Clear();
            dgvDefaultRules->Columns->Clear();

            // Setup columns
            dgvDefaultRules->Columns->Add("colId", "ID");
            dgvDefaultRules->Columns->Add("colName", "Name");
            dgvDefaultRules->Columns->Add("colSource", "Source");
            dgvDefaultRules->Columns->Add("colDest", "Destination");
            dgvDefaultRules->Columns->Add("colSrcPort", "Src Port");
            dgvDefaultRules->Columns->Add("colDestPort", "Dest Port");
            dgvDefaultRules->Columns->Add("colProtocol", "Protocol");
            dgvDefaultRules->Columns->Add("colAction", "Action");
            dgvDefaultRules->Columns->Add("colPriority", "Priority");
            dgvDefaultRules->Columns->Add("colTime", "Time");

            // Add rows for each default rule
            auto& rules = engine->getRules();
            for (const auto& rule : rules)
            {
                String^ timeStr = String::Empty;
                auto tbr = dynamic_cast<TimeBasedRule*>(rule.get());
                if (tbr != nullptr)
                {
                    timeStr = gcnew String(
                        (std::to_string(tbr->getStartHour()) + ".." + std::to_string(tbr->getEndHour())).c_str()
                    );
                }

                dgvDefaultRules->Rows->Add(
                    gcnew String(std::to_string(rule->getId()).c_str()),
                    gcnew String(rule->getName().c_str()),
                    gcnew String(rule->getSourceIpPattern().c_str()),
                    gcnew String(rule->getDestinationIpPattern().c_str()),
                    gcnew String(std::to_string(rule->getSourcePort()).c_str()),
                    gcnew String(std::to_string(rule->getDestinationPort()).c_str()),
                    gcnew String(rule->getProtocol().c_str()),
                    gcnew String(actionToString(rule->getAction()).c_str()),
                    gcnew String(std::to_string(rule->getPriority()).c_str()),
                    timeStr
                );
            }
        }


        void RefreshFileRulesGrid()
        {
            dgvFileRules->Rows->Clear();
            dgvFileRules->Columns->Clear();

            dgvFileRules->Columns->Add("colId", "ID");
            dgvFileRules->Columns->Add("colName", "Name");
            dgvFileRules->Columns->Add("colSource", "Source");
            dgvFileRules->Columns->Add("colDest", "Destination");
            dgvFileRules->Columns->Add("colSrcPort", "Src Port");
            dgvFileRules->Columns->Add("colDestPort", "Dest Port");
            dgvFileRules->Columns->Add("colProtocol", "Protocol");
            dgvFileRules->Columns->Add("colAction", "Action");
            dgvFileRules->Columns->Add("colPriority", "Priority");
            dgvFileRules->Columns->Add("colTime", "Time");
        }

        bool IsRuleIdDuplicateInFileRules(int ruleId)
        {
            for each(DataGridViewRow ^ row in dgvFileRules->Rows)
            {
                if (!row->IsNewRow && row->Cells["colId"]->Value != nullptr)
                {
                    if (Int32::Parse(row->Cells["colId"]->Value->ToString()) == ruleId)
                        return true;
                }
            }
            return false;
        }




        // Log message to system log
        void LogMessage(String^ message)
        {
            String^ timestamp = DateTime::Now.ToString("yyyy-MM-dd HH:mm:ss");
            rtbSystemLog->AppendText("[" + timestamp + "] " + message + "\n");
            rtbSystemLog->ScrollToCaret();
        }

        // Convert ActionType to string
        std::string actionToString(ActionType action)
        {
            switch (action)
            {
            case ActionType::ALLOW: return "ALLOW";
            case ActionType::DENY: return "DENY";
            case ActionType::LOG: return "LOG";
            default: return "UNKNOWN";
            }
        }

        // Packet capture thread method
        void CapturePackets()
        {
            int packetsToCapture = (int)numPacketsToCapture->Value;
            String^ encryptionKey = txtEncryptionKey->Text;
            bool encryptLogs = chkEncryptLogs->Checked;

            for (int i = 0; i < packetsToCapture && isCapturing; i++)
            {
                Packet capturedPacket = packetCapture->captureOnePacket();

                if (capturedPacket.sourceIp != "0.0.0.0" || capturedPacket.destinationIp != "0.0.0.0")
                {
                    // Evaluate the packet
                    ActionType action = engine->evaluatePacket(capturedPacket);

                    // Log to capture log
                    String^ packetInfo = gcnew String(capturedPacket.toString().c_str());
                    String^ actionTaken = gcnew String(actionToString(action).c_str());

                    this->Invoke(gcnew Action<String^, String^>(this, &MainForm::UpdateCaptureLog),
                        packetInfo, actionTaken);

                    // Log to file
                    std::string key = msclr::interop::marshal_as<std::string>(encryptionKey);
                    packetCapture->logPacketToFiles(capturedPacket, action, "packets.log", "packets.dat", key);
                }
                else
                {
                    i--; // Retry if packet capture failed
                }
            }

            this->Invoke(gcnew Action(this, &MainForm::StopCaptureUI));
        }

        // Update capture log from background thread
        void UpdateCaptureLog(String^ packetInfo, String^ actionTaken)
        {
            rtbCaptureLog->AppendText("Packet: " + packetInfo + "\n");
            rtbCaptureLog->AppendText("Action: " + actionTaken + "\n\n");
            rtbCaptureLog->ScrollToCaret();
        }

        // Stop capture and update UI
        void StopCaptureUI()
        {
            isCapturing = false;
            btnStartCapture->Enabled = true;
            btnStopCapture->Enabled = false;
            cmbNetworkDevices->Enabled = true;
            btnRefreshDevices->Enabled = true;
            LogMessage("Packet capture stopped");
        }

        // Stop capture
        void StopCapture()
        {
            isCapturing = false;
          
        }

        // Show SaveFileDialog on UI thread
        void ShowSaveFileDialogOnUIThread()
        {
            SaveFileDialog^ saveFileDialog = gcnew SaveFileDialog();
            saveFileDialog->Filter = "Log Files (*.log)|*.log|Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
            saveFileDialog->Title = "Save System Log";

            if (saveFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
            {
                try
                {
                    System::IO::File::WriteAllText(saveFileDialog->FileName, rtbSystemLog->Text);
                    LogMessage("System log saved to " + saveFileDialog->FileName);
                }
                catch (Exception^ ex)
                {
                    MessageBox::Show("Error saving log: " + ex->Message, "Error",
                        MessageBoxButtons::OK, MessageBoxIcon::Error);
                    LogMessage("Error saving log: " + ex->Message);
                }
            }
        }

  


    private:
        // Event handlers
        System::Void MainForm_Load(System::Object^ sender, System::EventArgs^ e)
        {
            LogMessage("Application started");
            btnRefreshDevices_Click(sender, e);
        }


        System::Void btnAddRule_Click(System::Object^ sender, System::EventArgs^ e)
        {
            int newId = engine->getNextAvailableId();
            if (dgvFileRules->Columns->Count == 0)
                RefreshFileRulesGrid();
            
            // Add to engine if needed (optional, for internal logic)
            engine->addRule(std::make_unique<::Rule>(
                newId,
                "New Rule " + std::to_string(newId),
                "ANY",
                "ANY",
                -1,
                -1,
                "TCP",
                ActionType::DENY,
                50
            )
            
            );

            // Add directly to dgvFileRules (do NOT clear the grid)
            dgvFileRules->Rows->Add(
                newId.ToString(),
                "New Rule " + newId,
                "ANY",
                "ANY",
                "-1",
                "-1",
                "TCP",
                "DENY",
                "50",
                "" // Time column empty for basic rule
            );

            LogMessage("Added new rule with ID " + newId);
        }

        System::Void btnRemoveRule_Click(System::Object^ sender, System::EventArgs^ e)
        {
            if (dgvFileRules->SelectedRows->Count > 0)
            {
                int selectedRowIndex = dgvFileRules->SelectedRows[0]->Index;
                int ruleId = Int32::Parse(dgvFileRules->Rows[selectedRowIndex]->Cells["colId"]->Value->ToString());

                // Optionally remove from engine if you want to keep them in sync
                 engine->deleteRule(ruleId);

                dgvFileRules->Rows->RemoveAt(selectedRowIndex);

                LogMessage("Removed rule with ID " + ruleId);
            }
            else
            {
                MessageBox::Show("Please select a rule to remove", "No Selection",
                    MessageBoxButtons::OK, MessageBoxIcon::Information);
            }
        }


        System::Void btnSaveRules_Click(System::Object^ sender, System::EventArgs^ e)
        {
            std::set<int> seenIds;
            for each(DataGridViewRow ^ row in dgvFileRules->Rows)
            {
                if (!row->IsNewRow && row->Cells["colId"]->Value != nullptr)
                {
                    int ruleId = Int32::Parse(row->Cells["colId"]->Value->ToString());
                    if (seenIds.find(ruleId) != seenIds.end())
                    {
                        MessageBox::Show("Duplicate rule IDs found in the file rules. Please ensure all rule IDs are unique before saving.", "Duplicate Rule IDs", MessageBoxButtons::OK, MessageBoxIcon::Error);
                        return;
                    }
                    seenIds.insert(ruleId);
                }
            }

            SaveFileDialog^ saveFileDialog = gcnew SaveFileDialog();
            saveFileDialog->Filter = "CSV Files (*.csv)|*.csv|LOG Files (*.log)|*.log|Encrypted Rules (*.dat)|*.dat|All Files (*.*)|*.*";
            saveFileDialog->Title = "Save Rules";

            


            if (saveFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
            {
                try
                {
                    String^ extension = System::IO::Path::GetExtension(saveFileDialog->FileName)->ToLower();
                    std::set<std::string> existingIds;
                    std::string filename = msclr::interop::marshal_as<std::string>(saveFileDialog->FileName);
                    bool fileExists = System::IO::File::Exists(saveFileDialog->FileName);

                    // 1. Read existing IDs from file (for .csv/.log only)
                    if ((extension == ".csv" || extension == ".log") && fileExists)
                    {
                        std::ifstream infile(filename);
                        std::string line;
                        bool isHeader = true;
                        while (std::getline(infile, line))
                        {
                            if (isHeader) { isHeader = false; continue; }
                            std::stringstream ss(line);
                            std::string id;
                            if (std::getline(ss, id, ','))
                            {
                                existingIds.insert(id);
                            }
                        }
                        infile.close();
                    }

                    System::Text::StringBuilder^ sb = gcnew System::Text::StringBuilder();

                    // Prepare rules as CSV string (for encryption or CSV)
                    if (extension == ".csv" || extension == ".dat")
                    {
                        if (!fileExists && extension == ".csv")
                            sb->AppendLine("ID,Name,Source,Destination,Src Port,Dest Port,Protocol,Action,Priority,Time");

                        for each (DataGridViewRow ^ row in dgvFileRules->Rows)
                        {
                            if (!row->IsNewRow)
                            {
                                std::string id = msclr::interop::marshal_as<std::string>(GetCellValueSafe(row, "colId"));
                                if (extension == ".dat" || existingIds.find(id) == existingIds.end())
                                {
                                    String^ timeVal = GetCellValueSafe(row, "colTime");
                                    if (!String::IsNullOrEmpty(timeVal))
                                        timeVal = "\"" + timeVal + "\"";
                                    sb->AppendFormat("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}\n",
                                        GetCellValueSafe(row, "colId"),
                                        GetCellValueSafe(row, "colName"),
                                        GetCellValueSafe(row, "colSource"),
                                        GetCellValueSafe(row, "colDest"),
                                        GetCellValueSafe(row, "colSrcPort"),
                                        GetCellValueSafe(row, "colDestPort"),
                                        GetCellValueSafe(row, "colProtocol"),
                                        GetCellValueSafe(row, "colAction"),
                                        GetCellValueSafe(row, "colPriority"),
                                        timeVal
                                    );
                                }
                            }
                        }
                    }

                    if (extension == ".dat")
                    {
                        // Prompt for encryption key
                        String^ keyStr = txtEncryptionKey->Text;
                        if (String::IsNullOrWhiteSpace(keyStr))
                        {
                           
                            keyStr = Interaction::InputBox(
                                gcnew String(L"Enter the encryption key for this rules file:"),
                                gcnew String(L"Encryption Key"),
                                gcnew String(L""),1,1);
                            if (String::IsNullOrWhiteSpace(keyStr))
                            {
                                MessageBox::Show("No encryption key provided.", "Aborted", MessageBoxButtons::OK, MessageBoxIcon::Warning);
                                return;
                            }
                        }
                        std::string key = msclr::interop::marshal_as<std::string>(keyStr);
                        std::string plainText = msclr::interop::marshal_as<std::string>(sb->ToString());
                        std::string encrypted = BasicFileEncryptor::encrypt(plainText, key);

                        // Write encrypted data to file
                        std::ofstream outfile(filename, std::ios::binary);
                        outfile.write(encrypted.c_str(), encrypted.size());
                        outfile.close();

                        LogMessage("Rules saved (encrypted) to: " + saveFileDialog->FileName);
                    }
                    else if (extension == ".csv")
                    {
                        System::IO::File::AppendAllText(saveFileDialog->FileName, sb->ToString());
                        LogMessage("New rules appended to: " + saveFileDialog->FileName);
                    }
                    else // LOG format
                    {
                        if (!fileExists)
                        {
                            sb->AppendLine("Network Rules Log");
                            sb->AppendLine("Generated: " + DateTime::Now.ToString());
                            sb->AppendLine("=================================");
                        }

                        for each (DataGridViewRow ^ row in dgvFileRules->Rows)
                        {
                            if (!row->IsNewRow)
                            {
                                std::string id = msclr::interop::marshal_as<std::string>(GetCellValueSafe(row, "colId"));
                                if (existingIds.find(id) == existingIds.end())
                                {
                                    sb->AppendFormat("[Rule: {0}]\n", GetCellValueSafe(row, "colName"));
                                    sb->AppendFormat("  Source: {0}:{1}\n", GetCellValueSafe(row, "colSource"), GetCellValueSafe(row, "colSrcPort"));
                                    sb->AppendFormat("  Destination: {0}:{1}\n", GetCellValueSafe(row, "colDest"), GetCellValueSafe(row, "colDestPort"));
                                    sb->AppendFormat("  Protocol: {0}\n", GetCellValueSafe(row, "colProtocol"));
                                    sb->AppendFormat("  Action: {0}\n", GetCellValueSafe(row, "colAction"));
                                    sb->AppendFormat("  Priority: {0}\n", GetCellValueSafe(row, "colPriority"));
                                    String^ timeVal = GetCellValueSafe(row, "colTime");
                                    if (!String::IsNullOrEmpty(timeVal))
                                        sb->AppendFormat("  Time: {0}\n", timeVal);
                                    sb->AppendLine("---------------------------------");
                                }
                            }
                        }
                        System::IO::File::AppendAllText(saveFileDialog->FileName, sb->ToString());
                        LogMessage("New rules appended to: " + saveFileDialog->FileName);
                    }
                }
                catch (Exception^ ex)
                {
                    MessageBox::Show("Error saving rules: " + ex->Message, "Error",
                        MessageBoxButtons::OK, MessageBoxIcon::Error);
                    LogMessage("Error saving rules: " + ex->Message);
                }
            }
        }

        // Helper function to safely get cell values
        String^ GetCellValueSafe(DataGridViewRow^ row, String^ columnName)
        {
            if (row->Cells[columnName] != nullptr && row->Cells[columnName]->Value != nullptr)
            {
                return row->Cells[columnName]->Value->ToString();
            }
            return String::Empty;  // Return empty string if column/cell doesn't exist
        }
        

        System::Void btnLoadRules_Click(System::Object^ sender, System::EventArgs^ e)
        {
            OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
            openFileDialog->Filter = "CSV Files (*.csv)|*.csv|LOG Files (*.log)|*.log|Encrypted Rules (*.dat)|*.dat|All Files (*.*)|*.*";
            openFileDialog->Title = "Load Rules";

            if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
            {
                try
                {
                    // Clear current rules in the engine
                    engine->clearAllRules();

                    String^ extension = System::IO::Path::GetExtension(openFileDialog->FileName)->ToLower();
                    std::string filePath = msclr::interop::marshal_as<std::string>(openFileDialog->FileName);
                    std::string rulesText;

                    if (extension == ".dat")
                    {
                        // Prompt for key if needed, or use txtEncryptionKey
                        String^ keyStr = txtEncryptionKey->Text;
                        if (String::IsNullOrWhiteSpace(keyStr))
                        
                        {
                            keyStr = Interaction::InputBox(
                                "Enter the encryption key for this rules file:",
                                "Decryption Key",
                                "",1,1);
                            if (String::IsNullOrWhiteSpace(keyStr))
                            {
                                MessageBox::Show("No decryption key provided.", "Aborted", MessageBoxButtons::OK, MessageBoxIcon::Warning);
                                return;
                            }
                        }
                        std::string key = msclr::interop::marshal_as<std::string>(keyStr);

                        // Read encrypted file
                        std::ifstream infile(filePath, std::ios::binary);
                        std::string encrypted((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
                        infile.close();

                        // Decrypt
                        rulesText = BasicFileEncryptor::decrypt(encrypted, key);
                    }
                    else if (extension == ".log")
                    {
                        RefreshFileRulesGrid();
                        std::ifstream infile(filePath);
                        std::string line;
                        std::string name, src, dst, proto, actionStr, timeStr;
                        int id = 0, srcPort = -1, dstPort = -1, priority = 0;
                        bool inRule = false;

                        while (std::getline(infile, line))
                        {
                            if (line.find("[Rule: ") == 0)
                            {
                                inRule = true;
                                // Extract rule name
                                size_t start = line.find("[Rule: ") + 7;
                                size_t end = line.find("]", start);
                                name = line.substr(start, end - start);
                            }
                            else if (inRule && line.find("Source: ") != std::string::npos)
                            {
                                size_t pos = line.find("Source: ") + 8;
                                std::string srcInfo = line.substr(pos);
                                size_t colon = srcInfo.find(":");
                                src = srcInfo.substr(0, colon);
                                srcPort = std::stoi(srcInfo.substr(colon + 1));
                            }
                            else if (inRule && line.find("Destination: ") != std::string::npos)
                            {
                                size_t pos = line.find("Destination: ") + 13;
                                std::string dstInfo = line.substr(pos);
                                size_t colon = dstInfo.find(":");
                                dst = dstInfo.substr(0, colon);
                                dstPort = std::stoi(dstInfo.substr(colon + 1));
                            }
                            else if (inRule && line.find("Protocol: ") != std::string::npos)
                            {
                                size_t pos = line.find("Protocol: ") + 10;
                                proto = line.substr(pos);
                            }
                            else if (inRule && line.find("Action: ") != std::string::npos)
                            {
                                size_t pos = line.find("Action: ") + 8;
                                actionStr = line.substr(pos);
                            }
                            else if (inRule && line.find("Priority: ") != std::string::npos)
                            {
                                size_t pos = line.find("Priority: ") + 9;
                                priority = std::stoi(line.substr(pos));
                            }
                            else if (inRule && line.find("Time: ") != std::string::npos)
                            {
                                size_t pos = line.find("Time: ") + 6;
                                timeStr = line.substr(pos);
                            }
                            else if (inRule && line.find("---------------------------------") == 0)
                            {
                                // Assign a unique ID (or parse if you add it to the log)
                                id++;
                                // Parse action
                                ActionType action = ActionType::DENY;
                                if (actionStr == "ALLOW") action = ActionType::ALLOW;
                                else if (actionStr == "LOG") action = ActionType::LOG;

                                // Add to engine and grid
                                if (!timeStr.empty())
                                {
                                    // Parse time range
                                    size_t sep = timeStr.find("..");
                                    int startHour = 0, endHour = 0;
                                    if (sep != std::string::npos)
                                    {
                                        startHour = std::stoi(timeStr.substr(0, sep));
                                        endHour = std::stoi(timeStr.substr(sep + 2));
                                    }
                                    engine->addRule(std::make_unique<TimeBasedRule>(
                                        id, name, src, dst, srcPort, dstPort, proto, action, priority, startHour, endHour
                                    ));
                                }
                                else
                                {
                                    engine->addRule(std::make_unique<::Rule>(
                                        id, name, src, dst, srcPort, dstPort, proto, action, priority
                                    ));
                                }

                                // Add to DataGridView
                                dgvFileRules->Rows->Add(
                                    gcnew String(std::to_string(id).c_str()),
                                    gcnew String(name.c_str()),
                                    gcnew String(src.c_str()),
                                    gcnew String(dst.c_str()),
                                    gcnew String(std::to_string(srcPort).c_str()),
                                    gcnew String(std::to_string(dstPort).c_str()),
                                    gcnew String(proto.c_str()),
                                    gcnew String(actionStr.c_str()),
                                    gcnew String(std::to_string(priority).c_str()),
                                    gcnew String(timeStr.c_str())
                                );

                                // Reset for next rule
                                name = src = dst = proto = actionStr = timeStr = "";
                                srcPort = dstPort = priority = 0;
                                inRule = false;
                            }
                        }
                        infile.close();
                        LogMessage("Rules loaded from " + openFileDialog->FileName);
                        return;
                    }
                    else
                    {
                        // Read plain text file
                        std::ifstream infile(filePath);
                        std::stringstream buffer;
                        buffer << infile.rdbuf();
                        rulesText = buffer.str();
                        infile.close();
                    }
                    RefreshFileRulesGrid();
                    // Parse rulesText as CSV (skip header)
                    std::istringstream iss(rulesText);
                    std::string line;
                    bool isHeader = true;
                    while (std::getline(iss, line))
                    {
                        if (isHeader) { isHeader = false; continue; }
                        if (line.empty()) continue;

                        std::stringstream ss(line);
                        std::string idStr, name, src, dst, srcPortStr, dstPortStr, proto, actionStr, priorityStr, timeStr;
                        std::getline(ss, idStr, ',');
                        std::getline(ss, name, ',');
                        std::getline(ss, src, ',');
                        std::getline(ss, dst, ',');
                        std::getline(ss, srcPortStr, ',');
                        std::getline(ss, dstPortStr, ',');
                        std::getline(ss, proto, ',');
                        std::getline(ss, actionStr, ',');
                        std::getline(ss, priorityStr, ',');
                        std::getline(ss, timeStr);

                        int id = std::stoi(idStr);
                        int srcPort = std::stoi(srcPortStr);
                        int dstPort = std::stoi(dstPortStr);
                        int priority = std::stoi(priorityStr);

                        // Remove quotes from timeStr if present
                        if (!timeStr.empty() && timeStr.front() == '"') timeStr = timeStr.substr(1, timeStr.size() - 2);

                        // Parse action
                        ActionType action = ActionType::DENY;
                        if (actionStr == "ALLOW") action = ActionType::ALLOW;
                        else if (actionStr == "LOG") action = ActionType::LOG;

                        // Check if this is a TimeBasedRule
                        if (!timeStr.empty())
                        {
                            // Expecting format: start..end
                            size_t sep = timeStr.find("..");
                            int startHour = 0, endHour = 0;
                            if (sep != std::string::npos)
                            {
                                startHour = std::stoi(timeStr.substr(0, sep));
                                endHour = std::stoi(timeStr.substr(sep + 2));
                            }
                            engine->addRule(std::make_unique<TimeBasedRule>(
                                id, name, src, dst, srcPort, dstPort, proto, action, priority, startHour, endHour
                            ));
                        }
                        else
                        {
                            engine->addRule(std::make_unique<::Rule>(
                                id, name, src, dst, srcPort, dstPort, proto, action, priority
                            ));
                        }

                        // Add rule to dgvFileRules
                        dgvFileRules->Rows->Add(
                            gcnew String(std::to_string(id).c_str()),
                            gcnew String(name.c_str()),
                            gcnew String(src.c_str()),
                            gcnew String(dst.c_str()),
                            gcnew String(std::to_string(srcPort).c_str()),
                            gcnew String(std::to_string(dstPort).c_str()),
                            gcnew String(proto.c_str()),
                            gcnew String(actionStr.c_str()),
                            gcnew String(std::to_string(priority).c_str()),
                            gcnew String(timeStr.c_str())
                        );
                    }

                    //RefreshDefaultRulesGrid();
                   
                    LogMessage("Rules loaded from " + openFileDialog->FileName);
                }
                catch (Exception^ ex)
                {
                    MessageBox::Show("Error loading rules: " + ex->Message, "Error",
                        MessageBoxButtons::OK, MessageBoxIcon::Error);
                    LogMessage("Error loading rules: " + ex->Message);
                }
            }
            
        }

        System::Void btnRefreshDevices_Click(System::Object^ sender, System::EventArgs^ e) {
            cmbNetworkDevices->Items->Clear();
            cmbNetworkDevices->BeginUpdate(); // Prevent flickering

            try {
                std::vector<NetworkDevice> device_system_names = packetCapture->listAvailableDevices();

                if (device_system_names.empty()) {
                    LogMessage("No network devices found or insufficient permissions");
                    MessageBox::Show("No network devices found or insufficient permissions. Try running as administrator.",
                        "No Devices", MessageBoxButtons::OK, MessageBoxIcon::Warning);
                    return;
                }

                for (const auto& device : device_system_names) {
                    // Use marshal_as for safe conversion
                    String^ netDevice = msclr::interop::marshal_as<System::String^>(device.description);
                    if (!String::IsNullOrWhiteSpace(netDevice)) {
                        cmbNetworkDevices->Items->Add(netDevice);
                    }
                }

                if (cmbNetworkDevices->Items->Count > 0) {
                    cmbNetworkDevices->SelectedIndex = 0;
                }
                LogMessage("Refreshed network devices list - Found " + cmbNetworkDevices->Items->Count + " devices");
            }
            catch (Exception^ ex) {
                LogMessage("Error refreshing devices: " + ex->Message);
                MessageBox::Show("Error refreshing network devices: " + ex->Message,
                    "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
            }
            finally {
                cmbNetworkDevices->EndUpdate();
            }
        }

        System::Void btnStartCapture_Click(System::Object^ sender, System::EventArgs^ e)
        {
            if (cmbNetworkDevices->SelectedItem == nullptr)
            {
                MessageBox::Show("Please select a network device first", "No Device Selected",
                    MessageBoxButtons::OK, MessageBoxIcon::Information);
                return;
            }

            String^ selectedDevice = cmbNetworkDevices->SelectedItem->ToString();
           // std::string selectedDeviceStr = msclr::interop::marshal_as<std::string>(selectedDevice);
			std::vector<NetworkDevice> devices = packetCapture->listAvailableDevices();
            for (const auto& device : devices) {
                if (device.description == msclr::interop::marshal_as<std::string>(selectedDevice))                   
                {
                    packetCapture->setDevice((device.name));
                }
            }

            //packetCapture->setDevice(msclr::interop::marshal_as<std::string>(selectedDevice));

            isCapturing = true;
            btnStartCapture->Enabled = false;
            btnStopCapture->Enabled = true;
            cmbNetworkDevices->Enabled = false;
            btnRefreshDevices->Enabled = false;

            rtbCaptureLog->Clear();
            LogMessage("Starting packet capture on device: " + selectedDevice);

            // Start capture in background thread
            captureThread = gcnew Thread(gcnew ThreadStart(this, &MainForm::CapturePackets));
            captureThread->Start();
        }

        System::Void btnStopCapture_Click(System::Object^ sender, System::EventArgs^ e)
        {
            StopCapture();
            LogMessage("Packet capture stopped by user");
        }

        System::Void chkEncryptLogs_CheckedChanged(System::Object^ sender, System::EventArgs^ e)
        {
            txtEncryptionKey->Enabled = chkEncryptLogs->Checked;
            LogMessage("Log encryption " + (chkEncryptLogs->Checked ? "enabled" : "disabled"));
        }

        System::Void btnBrowsePacketFile_Click(System::Object^ sender, System::EventArgs^ e)
        {
            OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
            openFileDialog->Filter = "CSV Files (*.csv)|*.csv|LOG Files (*.log)|*.log|All Files (*.*)|*.*";
            openFileDialog->Title = "Select Packet File";

            if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
            {
                txtPacketFilePath->Text = openFileDialog->FileName;
            }
        }

        System::Void btnAnalyzeFile_Click(System::Object^ sender, System::EventArgs^ e) {
            if (String::IsNullOrEmpty(txtPacketFilePath->Text)) {
                MessageBox::Show("Please select a packet file first", "No File Selected",
                    MessageBoxButtons::OK, MessageBoxIcon::Information);
                return;
            }

            try {
                rtbAnalysisResults->Clear();
                std::string filePath = msclr::interop::marshal_as<std::string>(txtPacketFilePath->Text);

                // Analyze the file and get results
                std::string analysisResult = engine->analyzePacketFileAndGetResults(filePath);

                // Display results in the rich text box
                rtbAnalysisResults->Text = gcnew String(analysisResult.c_str());
                LogMessage("Analyzed packet file: " + txtPacketFilePath->Text);
            }
            catch (Exception^ ex) {
                MessageBox::Show("Error analyzing file: " + ex->Message, "Error",
                    MessageBoxButtons::OK, MessageBoxIcon::Error);
                LogMessage("Error analyzing file: " + ex->Message);
            }
        }

        System::Void btnClearLogs_Click(System::Object^ sender, System::EventArgs^ e)
        {
            rtbSystemLog->Clear();
            LogMessage("System logs cleared");
        }

        System::Void btnSaveLogs_Click(System::Object^ sender, System::EventArgs^ e)
        {
            this->Invoke(gcnew MethodInvoker(this, &MainForm::ShowSaveFileDialogOnUIThread));
        }
    };

}