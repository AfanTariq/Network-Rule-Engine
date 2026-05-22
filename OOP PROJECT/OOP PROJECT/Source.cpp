//#include <iostream>
//#include <vector>
//#include <string>
//#include <fstream>
//#include <limits>
//
//#include "RuleEngine.h"
//#include "Rule.h"
//#include "TimeBasedRule.h"
//#include "Packet.h"
//#include "NetworkPacketCapture.h"
//#include "BasicFileEncryptor.h" // 🔐 Include the encryptor
//
//int main() {
//    std::cout << "Advanced Logic & Novelty Demo with Real Network Packet Capture" << std::endl;
//    std::cout << "===========================================================================================\n" << std::endl;
//
//
//
//
//    RuleEngine engine(ActionType::DENY, "engine_traffic_with_real_capture.log");
//
//    // --- Add Rules ---
//    std::cout << "\n--- Adding Rules ---" << std::endl;
//    engine.addRule(std::make_unique<Rule>(engine.getNextAvailableId(), "Allow Corp Web HTTPS", "ANY", "10.0.1.0/24", -1, 443, "TCP", ActionType::ALLOW, 50));
//    engine.addRule(std::make_unique<Rule>(engine.getNextAvailableId(), "Allow Corp Web HTTP", "ANY", "10.0.1.0/24", -1, 80, "TCP", ActionType::ALLOW, 40));
//    engine.addRule(std::make_unique<TimeBasedRule>(engine.getNextAvailableId(), "Allow FTP (Work Hours)", "ANY", "ANY", -1, 62774, "TCP", ActionType::ALLOW, 30, 9, 23));
//    engine.addRule(std::make_unique<Rule>(engine.getNextAvailableId(), "Block Bad Site", "ANY", "6.6.6.6", -1, -1, "ANY", ActionType::DENY, 100));
//    engine.addRule(std::make_unique<Rule>(engine.getNextAvailableId(), "Override Block Bad Site", "ANY", "6.6.6.6", -1, -1, "ANY", ActionType::ALLOW, 110));
//    engine.addRule(std::make_unique<Rule>(engine.getNextAvailableId(), "Log All Web to Corp", "ANY", "10.0.1.0/24", -1, 443, "TCP", ActionType::LOG, 45));
//    engine.addRule(std::make_unique<Rule>(engine.getNextAvailableId(), "Allow Local DNS", "ANY", "ANY", -1, 53, "UDP", ActionType::ALLOW, 60));
//    engine.addRule(std::make_unique<Rule>(engine.getNextAvailableId(), "Allow Local DNS", "ANY", "ANY", -1, 53, "TCP", ActionType::ALLOW, 60));
//    engine.addRule(std::make_unique<Rule>(engine.getNextAvailableId(), "Allow DHCP", "ANY", "ANY", 68, 67, "UDP", ActionType::ALLOW, 70));
//
//    engine.displayAllRules();
//
//    // --- Initialize Network Capture ---
//    std::cout << "\n--- Network Packet Capture ---" << std::endl;
//    NetworkPacketCapture packetCapture("");
//
//    std::vector<std::string> system_names_for_devices = packetCapture.listAvailableDevices();
//
//    if (system_names_for_devices.empty()) {
//        std::cout << "No devices found or insufficient permissions to access network devices." << std::endl;
//        std::cout << "Try running this program as administrator/root." << std::endl;
//        return 1;
//    }
//
//    std::string selected_system_name;
//    if (system_names_for_devices.size() == 1) {
//        selected_system_name = system_names_for_devices[0];
//        std::cout << "Automatically selected the only available device." << std::endl;
//    }
//    else {
//        int deviceChoice = 0;
//        std::cout << "Select device number (1-" << system_names_for_devices.size() << "): ";
//        std::cin >> deviceChoice;
//
//        if (!(deviceChoice >= 1 && deviceChoice <= static_cast<int>(system_names_for_devices.size()))) {
//            std::cout << "Invalid choice. Defaulting to first device.\n";
//            deviceChoice = 1;
//        }
//        selected_system_name = system_names_for_devices[deviceChoice - 1];
//
//    }
//
//    packetCapture.setDevice(selected_system_name);
//    std::cout << "Using device (system name): " << selected_system_name << std::endl;
//
//    // --- Capture and Evaluate Packets ---
//    std::cout << "\n--- Capturing and Evaluating Real Network Traffic ---" << std::endl;
//    std::cout << "Capturing 10 packets..." << std::endl;
//
//    const int captureCount = 10;
//    const std::string encryptionKey = "mySecretKey123";
//    const std::string encryptedCSV = "packets_encrypted.csv";
//
//    for (int i = 0; i < captureCount; ++i) {
//        std::cout << "\nCapturing packet " << (i + 1) << "/" << captureCount << "..." << std::endl;
//        Packet capturedPacket = packetCapture.captureOnePacket();
//
//        if (capturedPacket.sourceIp != "0.0.0.0" || capturedPacket.destinationIp != "0.0.0.0") {
//            std::cout << "Captured real packet:\n";
//
//            // Evaluate the packet and store the action
//            ActionType action = engine.evaluatePacket(capturedPacket);
//
//            // Output the result to console
//            std::cout << "Packet Info: " << capturedPacket.toString() << std::endl;
//            std::cout << "Action Taken: " << actionToString(action) << std::endl;
//
//            // Log the packet info and action to file
//            packetCapture.logPacketToFiles(capturedPacket, action, "packets.log", "packets.dat", "mySecretKey123");
//        }
//        else {
//            std::cout << "Failed to capture a valid packet. Retrying..." << std::endl;
//            --i;
//        }
//    }
//
//    std::cout << "\nDemonstration complete. Encrypted log written to '" << encryptedCSV << "'." << std::endl;
//
//  
//    std::cout << "\nWould you like to analyze a packet file? (y/n): ";
//    char choice;
//    std::cin >> choice;
//
//    if (choice == 'y' || choice == 'Y') {
//        std::string temp;
//        std::getline(std::cin, temp);  // Clear the leftover newline from previous input
//
//        std::cout << "Enter path to packet file: ";
//        std::string packetFile;
//        std::getline(std::cin, packetFile);
//
//        // Assuming engine is defined and has analyzePacketFile method
//         engine.analyzePacketFile(packetFile);
//        std::cout << "Analyzing file: " << packetFile << std::endl; // Placeholder
//    }
//    return 0;
//}
