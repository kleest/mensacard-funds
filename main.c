#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <freefare.h>

int main(int argc, char *argv[]) {
    nfc_device *device = NULL;
    nfc_connstring devices[1];
    size_t device_count;

    // initialize NFC and NFC device
    nfc_context *context;
    nfc_init(&context);
    if (context == NULL)
        errx(EXIT_FAILURE, "Unable to init libnfc");

    device_count = nfc_list_devices(context, devices, 1);
    if (device_count <= 0)
        errx(EXIT_FAILURE, "No NFC device found.");

    device = nfc_open(context, devices[0]);
    if (!device)
        errx(EXIT_FAILURE, "nfc_open() failed.");

    // scan for target tags in a loop
    FreefareTag tag;
    do {
        nfc_modulation modulation = {
                .nmt = NMT_ISO14443A,
                .nbr = NBR_106
        };
        nfc_target target;
        int res = nfc_initiator_poll_target(device, &modulation, 1, 0xff, 0x10, &target);
        if (res < 0)
            errx(EXIT_FAILURE, "Error finding any target");

        // We cannot use freefare_tag_new here because this would check for a passive tag which does not work when
        // relaying the card using NFCGate.
        tag = mifare_desfire_tag_new(device, target);

        if (tag == NULL)
            warnx("Cannot connect to target");

        // sleep 100ms before polling for targets again
        usleep(100000);
    } while (tag == NULL);

    if (MIFARE_DESFIRE != freefare_get_tag_type(tag))
        errx(EXIT_FAILURE, "No DESFire card");

    // print card UID
    char *tag_uid = freefare_get_tag_uid(tag);
    printf("Found %s with UID %s.\n", freefare_get_tag_friendly_name(tag), tag_uid);

    // connect using DESFire
    int res = mifare_desfire_connect(tag);
    if (res < 0)
        errx(EXIT_FAILURE, "Can't connect to Mifare DESFire target.");

    // Mifare DESFire SelectApplication
    MifareDESFireAID aid = mifare_desfire_aid_new(0x15845F);

    res = mifare_desfire_select_application(tag, aid);
    if (res < 0)
        errx(EXIT_FAILURE, "Application selection failed: %d", res);

    // query and display the current funds
    int val;
    res = mifare_desfire_get_value(tag, 1, &val);
    if (res < 0)
        errx(EXIT_FAILURE, "Reading value of fileno 1 failed: %d", res);
    printf("Current funds:\t\t\t %.2f €\n", val/1000.0f);

    // query and display last transaction valuta
    struct mifare_desfire_file_settings settings;
    res = mifare_desfire_get_file_settings(tag, 1, &settings);
    if (res < 0)
        errx(EXIT_FAILURE, "Reading file settings of fileno 1 failed: %d", res);
    printf("Last transaction:\t\t %.2f €\n", settings.settings.value_file.limited_credit_value/1000.0f);

    // cleanup
    free(aid);
    mifare_desfire_disconnect(tag);
    free(tag_uid);
    nfc_close(device);
    nfc_exit(context);

    exit(EXIT_SUCCESS);
}
