/* [ATTENZIONE] - prima implementazione molto spoglia questa e solo per test per identificare possibili vie da migliorare assolutamente 

windows version
#include <windows.h>
#include <iostream>

void ListInputDevices() {
    UINT numDevices;
    GetRawInputDeviceList(nullptr, &numDevices, sizeof(RAWINPUTDEVICELIST));

    RAWINPUTDEVICELIST* devices = new RAWINPUTDEVICELIST[numDevices];
    GetRawInputDeviceList(devices, &numDevices, sizeof(RAWINPUTDEVICELIST));

    for (UINT i = 0; i < numDevices; ++i) {
        RID_DEVICE_INFO deviceInfo;
        deviceInfo.cbSize = sizeof(RID_DEVICE_INFO);
        UINT size = sizeof(deviceInfo);
        GetRawInputDeviceInfo(devices[i].hDevice, RIDI_DEVICEINFO, &deviceInfo, &size);

        if (deviceInfo.dwType == RIM_TYPEKEYBOARD) {
            std::cout << "Tastiera trovata\n";
        } else if (deviceInfo.dwType == RIM_TYPEMOUSE) {
            std::cout << "Mouse trovato\n";
        } else if (deviceInfo.dwType == RIM_TYPEHID) {
            std::cout << "Dispositivo HID generico\n";
        }
    }

    delete[] devices;
}
*/

// linux version 
/*
/*#include "iostream"
#include "libudev.h"
#include "cstring"

using namespace std;

void ListInputDevice() {
    struct udev* udev = udev_new();
    if (!udev) {
        std::cerr << "[-] - errore inatteso si prega di risolvere per poter proseguire!!.\n";
        return;
    }

    struct udev_enumerate* enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "input");

    udev_enumerate_scan_devices(enumerate);
    
    // tutto cio dovra succesivamente essere passato in maniera sicuor per mezzo di infostruct
    struct udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate);
    struct udev_list_entry* dev_list_entry;

    std::cout << "[*] - e partita l'analisi delle periferiche!!.\n";

    udev_list_entry_foreach(dev_list_entry, devices) {
        const char* path = udev_list_entry_get_name(dev_list_entry);
        struct udev_device* dev = udev_device_new_from_syspath(udev, path);

        if (dev) {
            const char* tastiera = udev_device_get_property_value(dev, "ID_INPUT_KEYBOARD");
            const char* mouse = udev_device_get_property_value(dev, "ID_INPUT_MOUSE");

            const char* name = udev_device_get_sysattr_value(dev, "name");
            if (!name) {
                name = "[DEBUG] - dispositivo senza nome";
            }

            if (tastiera && strcmp(tastiera, "1") == 0) {
                std::cout << "[+] - tastiera rinvenuta" << name << " (" << udev_device_get_devnode(dev) << ")\n";
            }

            if (mouse && strcmp(mouse, "1") == 0) {
                std::cout << "[+] tastiera trovata" << name << " (" << udev_device_get_devnode(dev) << ")\n";
            }

            udev_device_unref(dev);
        }
    }

    udev_enumerate_unref(enumerate);
    udev_unref(udev);
}


int main() {
    ListInputDevice();
    return 0;
} */

    #include <iostream>
    #include <fcntl.h>
    #include <unistd.h>
    #include <linux/input.h>

    int main() {
        int fd = open("/dev/input/eventX", O_RDONLY); // Sostituisci 'X' con il numero corretto
        if (fd < 0) {
            perror("Errore nell'apertura del file");
            return 1;
        }

        struct input_event ev;
        while (read(fd, &ev, sizeof(struct input_event)) == sizeof(struct input_event)) {
            std::cout << "Tipo evento: " << ev.type << ", Codice: " << ev.code << ", Valore: " << ev.value << std::endl;
        }

        close(fd);
        return 0;
    }