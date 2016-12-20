# ArduinoGPRSlogger
Catcher GPRS communication on serial TTL and store in on SD card for WireShark

HW Arduino Uno R3
See www.arduuino.cc

Serial TTL
- Attention: Use serial wire on TTL no RS232.
- Connect these pins directly to an RS232 serial port; they operate at +/- 12V
  and can damage your Arduino board.
  See https://www.arduino.cc/en/Tutorial/ArduinoSoftwareRS232
- Default is 38400 baud and 8N1, see setup() function

Date/Time
- Official routines are not possible compiled and occupy too much space. It does not use hardware support. Do not expect miracles because it's just a software emulation depends on running software and ambient temperature. The variable local_time (T_DateTime structure) stores the current Date/Time. When is changing the second that upgrade this structure with timeCounter() and show it on the DSP using timeShowClock().
 - each 5-minute (see constant DT_STORE_MINUTE) the time is stored into the local EEPROM
 - during starting device is read from EEPROM last saved Date/Time
 - by constant TIME_LEAP is possible these simple clock adjusted
 - date accepts leap years, does not accept summer / winter time
 - UTC offset for WireShark can be defined in UTC_SHIFT

DSP
- Using HW buy on eBay www.mcufriend.com (IDF=0x154) 240x320 pixels.
- Use routine Adafruit it should be downloaded from https://github.com/adafruit/Adafruit-GFX-Library and https://github.com/adafruit/TFTLCD-Library.

Settings DSP:
- define LCD_CS A3    // Chip Select goes to Analog 3
- define LCD_CD A2    // Command/Data goes to Analog 2
- define LCD_WR A1    // LCD Write goes to Analog 1
- define LCD_RD A0    // LCD Read goes to Analog 0
- define LCD_RESET A4 // Can alternately just connect to Arduino's reset pin
- define YP A1  // must be an analog pin, use "An" notation!
- define XM A2  // must be an analog pin, use "An" notation!
- define YM 7   // can be a digital pin
- define XP 6   // can be a digital pin

- Consult from your hardware. SW is debugged for Identificator IDF=0x154. Chip NXP HC245 DY8400S TXD442E
- design of screen is possible change in tftHomeScreen() function

TFT DSP contain SD card reader
- SD Card is initialized at startup if no then it is checked every 5 seconds (see constant SD_INIT_TIME)

If the card is initialized then
- create the LOG directory
- create a subdirectory /LOG/DDD counter shall be increased every reset
- opens a file called /LOG/DDD/MMDDHHMM.raw (/LOG/DDD/MMDDHHMM.cap)
  Accordingly, whether to log the raw data or pre-processed for wireshark
- raw data includes a header defined in struct pcap_pkthdr, file begins with a header as defined in the struct pcap_file_header. Files can be read in Wireshark in this version because not replace char 0x7D or delimiter of packet 0x7E.
- if communication is in idle more than 5 minutes (see GPRS_SUSPEND_TIME constant), then the file is closed and opens a new with actual time in filename.
- the SD card will store data immediately. It can be removed at any time.
- sw don't format the card or not clear data (but must have a supported format FAT16, FAT32)
- if you want change the constant LOG_FILE note that SD routines can work with file format 8 + 3
- SW catched data in RAW format without replacement 0x7D and divide 0x7E. If you want see Wireshark format plase use \Normalize\GPRS_norm.exe
  or \Normalize\normalize.bat for all files in subdirectories.