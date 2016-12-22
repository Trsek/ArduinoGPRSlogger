/*
  GPRSlogger - Arduino Catcher GPRS communication on serial TTL and store it on SD card (for WireShark use)
  Software by Zdeno Sekerak (c) 2015. www.trsek.com/en/curriculum

  This software is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#include <SPI.h>
#include <SD.h>
#include <EEPROM.h>
#include <avr/wdt.h>
#include <Adafruit_GFX.h>    // Core graphics library
#include <Adafruit_TFTLCD.h> // Hardware-specific library

#define LOG_FILE "/LOG/XXX/MMDDHHMM.cap"
#define LOG_SUBDIR_IND   5   // index of 2th location char '/' in LOG_FILE
#define LOG_DELIMITER    8   // index of 3th location char '/' in LOG_FILE
//#define ECHO_ON_SERIAL     // uncomment - enable echo on serial port, is possible see data in "Serial monitor" or catch with PC software
//#define FORCE_TIME         // uncomment - if you want force new Date/Time (see setup() function)

#define DT_STORE_MINUTE  5   // every 5 minutes write to actually time to EEPROM
#define SD_INIT_TIME     5   // every 6 seconds check SD card ready if is not available
#define GPRS_SUSPEND_TIME  ((unsigned long)60*60*COUNT_SECOND)  // (milisecond) how long silence on line is deemed as communication finish
#define TIME_LEAP    -151L   // leap ms per minute. Check how many milisecond clock different per long time and compute it.

// SD card chip selected
#define SD_CHIP_SELECTED 10   // for device from www.mcufriend.com (IDF=0x154)

// The control pins for the LCD can be assigned to any digital or
// analog pins...but we'll use the analog pins as this allows us to
// double up the pins with the touch screen (see the TFT paint example).
// for device from www.mcufriend.com (IDF=0x154)
#define LCD_CS A3    // Chip Select goes to Analog 3
#define LCD_CD A2    // Command/Data goes to Analog 2
#define LCD_WR A1    // LCD Write goes to Analog 1
#define LCD_RD A0    // LCD Read goes to Analog 0
#define LCD_RESET A4 // Can alternately just connect to Arduino's reset pin

// Assign human-readable names to some common 16-bit color values:
#define BLACK   0x0000
#define BLUE    0x001F
#define RED     0xF800
#define GREEN   0x07E0
#define CYAN    0x07FF
#define MAGENTA 0xF81F
#define YELLOW  0xFFE0
#define WHITE   0xFFFF

// These are the pins for the shield!
// for device from www.mcufriend.com (IDF=0x154)
#define YP A1  // must be an analog pin, use "An" notation!
#define XM A2  // must be an analog pin, use "An" notation!
#define YM 7   // can be a digital pin
#define XP 6   // can be a digital pin

Adafruit_TFTLCD tft(LCD_CS, LCD_CD, LCD_WR, LCD_RD, LCD_RESET);

// defines for second constants
#define COUNT_SECOND      1000  // how many milliseconds need for second
#define SEC_PER_MIN         60  // per minute
#define SEC_PER_HOUR      3600  // per hour
#define SEC_PER_DAY      86400  // per day (24*60*60)
#define SEC_FOR_Y2K    946684800UL
#define UTC_SHIFT           1L  // + 1 UTC for Prague

// defines for log view
#define LOG_Y         145
#define LOG_HEIGHT    160   // 20 lines (LOG_HEIGHT / FONT_HEIGHT)
#define FONT_WIDTH      6
#define FONT_HEIGHT     8

#define DT_MARK0 'D'
#define DT_MARK1 'T'

#define __MONTH__ (\
      __DATE__[2] == 'n' ? (__DATE__[1] == 'a' ? 1 : 6) \
    : __DATE__[2] == 'b' ? 2 \
    : __DATE__[2] == 'r' ? (__DATE__[0] == 'M' ? 3 : 4) \
    : __DATE__[2] == 'y' ? 5 \
    : __DATE__[2] == 'l' ? 7 \
    : __DATE__[2] == 'g' ? 8 \
    : __DATE__[2] == 'p' ? 9 \
    : __DATE__[2] == 't' ? 10 \
    : __DATE__[2] == 'v' ? 11 \
    : 12)

static byte monthDays[] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
static unsigned short yearDays[] = {0,31,59,90,120,151,181,212,243,273,304,334};

#define PPP_DELIMITER  0x7E
#define PPP_REPLACE    0x7D
#define PCAP_HEADER {0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00};
// -----------------------------------------------------------------------------

typedef struct {
   unsigned long magic;
   unsigned short version_major; 
   unsigned short version_minor; 
   signed long thiszone; 
   unsigned long sigfigs;    
   unsigned long snaplen;    
   unsigned long linktype;   
} pcap_file_header;

typedef struct  {
   unsigned long tv_sec;
   unsigned long tv_usec;
   unsigned long caplen; 
   unsigned long len;    
} pcap_pkthdr;

typedef struct {
  unsigned long lastMillis;
  unsigned short year;
  unsigned char month;
  unsigned char day;
  unsigned char hour;
  unsigned char minute;
  unsigned char second;
  unsigned short milisecond;
  unsigned long unixTime;
  signed short leap;      // leap time -> ms per minute
  unsigned char change_Date:1, change_Hour:1, change_Minute:1, change_Second:1;
} T_DateTime;

typedef struct {
  short X;
  short Y;
  short clearY;
} T_Terminal;
// -----------------------------------------------------------------------------

T_DateTime local_time;
T_Terminal terminal;
File dataFile;
char serial_buffer[192];    // maximum of arduino interrupt
unsigned long timeSuspend;  // check time when on wire is quiet
unsigned long charCounter;
short dirCounter;           // counter of dir /LOG/XXX/ on SD card
// -----------------------------------------------------------------------------


void setup(void) 
{
  // default time
  local_time.year   = 2000 + atoi2(__DATE__ + 9);
  local_time.month  = __MONTH__;
  local_time.day    = atoi2(__DATE__ + 4);
  local_time.hour   = atoi2(__TIME__);
  local_time.minute = atoi2(__TIME__ + 3);
  local_time.second = atoi2(__TIME__ + 6);
  local_time.milisecond = 0;
#ifdef FORCE_TIME
  EEPROM[0] = '\0';   // damage control byte in timeEPROM (rountine timeEEPROM() save it)
#endif
  timeEEPROM(false);  // read from EEPROM last know time
  local_time.leap = TIME_LEAP;
  local_time.change_Hour = true;
  local_time.change_Minute = true;
  local_time.change_Second = true;
  local_time.change_Date = true;
  local_time.unixTime = timeUnix();

  Serial.begin(38400, SERIAL_8N1);
  Serial.setTimeout(100);
#ifndef ECHO_ON_SERIAL
  Serial.println(F("GPRS traffic logger. Software by Zdeno Sekerak (c) 2016."));
#endif

  tft.reset();
  tft.begin(tft.readID());
  tftHomeScreen();
  timeShowClock(39);

  // init SD card and open file for store
  dirCounter = 0;
  sdInit();
  sdMakeNew();

  // terminal
  terminalInit();
  timeSuspend = millis();
  charCounter = 0;

  // enable watchdog
  wdt_enable(WDTO_8S);
}
// -----------------------------------------------------------------------------


void loop(void) 
{
   unsigned short readLength;

   // something on serial channel
   // i rounding when data incomming (this is most important)
   while( Serial.available())
   {
       readLength = Serial.readBytes(serial_buffer, sizeof(serial_buffer));
       if (dataFile)
       {
           if( readLength ) 
              pcapStore(serial_buffer, readLength);
       }

       terminalShow(serial_buffer, readLength);
#ifdef ECHO_ON_SERIAL
       Serial.write(serial_buffer, readLength);
#endif
       timeSuspend = millis();
       charCounter += readLength;
   }

   // try initialize SD card if it is not available
   if((( local_time.second % SD_INIT_TIME ) == 0)
   && !dataFile )
   {
      sdInit();
      sdMakeNew();
   }
   
   // clock runtime
   if( timeCounter())
   {
      timeShowClock(39);
      timeEEPROM(true);   // every 5 min store it

      // when data more than 60 minutes not incomming then close and open next file
      if(( charCounter > 0 )
      && ((millis() - timeSuspend) >= GPRS_SUSPEND_TIME ))
      {
        // close
        if (dataFile)
        {
           dataFile.close();
           // open next file in order
           charCounter = 0;
           sdMakeNew();
        }
      }
  } // if( timeCounter())

  // reset watchdog
  wdt_reset();
}
// -----------------------------------------------------------------------------


// callback for SD rountine
void dateTime(uint16_t* date, uint16_t* time) 
{
  // return date using FAT_DATE macro to format fields
  *date = FAT_DATE(local_time.year, local_time.month, local_time.day);

  // return time using FAT_TIME macro to format fields
  *time = FAT_TIME(local_time.hour, local_time.minute, local_time.second);
}
// -----------------------------------------------------------------------------


// check directory "/LOG/XXX/" or make it
bool sdInit()
{
  char strLOG_FILE[] = { LOG_FILE };
  
  if (!SD.begin(SD_CHIP_SELECTED)) {
    return false;
  }

  SdFile::dateTimeCallback(dateTime);
  strLOG_FILE[ LOG_SUBDIR_IND ] = '\0';

  // make main LOG directory
  if( !SD.exists(strLOG_FILE)) {
    SD.mkdir(strLOG_FILE);
  }

  // subdirectory
  strLOG_FILE[ LOG_SUBDIR_IND ] = '/';
  strLOG_FILE[ LOG_DELIMITER ] = '\0';

  do {
    dirCounter++;
    dirCounter = dirCounter % 1000;   // max 999
    strLOG_FILE[ LOG_SUBDIR_IND    ] = '0' + (dirCounter / 100);
    strLOG_FILE[ LOG_SUBDIR_IND + 1] = '0' + ((dirCounter % 100) / 10);
    strLOG_FILE[ LOG_SUBDIR_IND + 2] = '0' + (dirCounter % 10);
  } while( SD.exists( strLOG_FILE ));

  // I will do subdirectory /LOG/001
  if( !SD.exists( strLOG_FILE ))
    SD.mkdir( strLOG_FILE );

  return true;
}
// -----------------------------------------------------------------------------


// open new file and ready for writing
void sdMakeNew()
{
  char strLOG_FILE[] = { LOG_FILE };
  unsigned char pcapHeader[] = PCAP_HEADER;

  // subdir
  strLOG_FILE[ LOG_SUBDIR_IND    ] = '0' + (dirCounter / 100);
  strLOG_FILE[ LOG_SUBDIR_IND + 1] = '0' + ((dirCounter % 100) / 10);
  strLOG_FILE[ LOG_SUBDIR_IND + 2] = '0' + (dirCounter % 10);
  
  // date
  strLOG_FILE[LOG_DELIMITER + 1] = (local_time.month / 10) + '0';
  strLOG_FILE[LOG_DELIMITER + 2] = (local_time.month % 10) + '0';
  strLOG_FILE[LOG_DELIMITER + 3] = (local_time.day / 10) + '0';
  strLOG_FILE[LOG_DELIMITER + 4] = (local_time.day % 10) + '0';

  // time
  strLOG_FILE[LOG_DELIMITER + 5] = (local_time.hour / 10) + '0';
  strLOG_FILE[LOG_DELIMITER + 6] = (local_time.hour % 10) + '0';
  strLOG_FILE[LOG_DELIMITER + 7] = (local_time.minute / 10) + '0';
  strLOG_FILE[LOG_DELIMITER + 8] = (local_time.minute % 10) + '0';

  // close if open
  if ( dataFile )
    dataFile.close();

  // open it
  dataFile = SD.open(strLOG_FILE, FILE_WRITE);
  dataFile.write(pcapHeader, sizeof(pcapHeader));
  dataFile.flush();

  // and show it
  sdShowFileName(125, strLOG_FILE);
}
// -----------------------------------------------------------------------------


// local_time convert to unix format
unsigned long timeUnix()
{
  unsigned long unix_time;
  unsigned char leap;

  unix_time = 
           (unsigned long)local_time.second 
         + (unsigned long)local_time.minute * SEC_PER_MIN 
         + (unsigned long)local_time.hour * SEC_PER_HOUR
         + ((unsigned long)local_time.day -1 + (unsigned long)yearDays[ local_time.month-1 ]) * SEC_PER_DAY 
         + (unsigned long)(local_time.year - 2000) * SEC_PER_DAY * 365;
         
  leap = ((local_time.year - 2000)/4) + 1;
  if (( local_time.year % 4) == 0 ) {
      if (local_time.month < 3)
          leap--;
  }

  unix_time +=  (unsigned long)leap * SEC_PER_DAY + SEC_FOR_Y2K - (UTC_SHIFT * SEC_PER_HOUR);
  return unix_time;
}
// -----------------------------------------------------------------------------


// save incomming packet
void pcapStore(char *serial_buffer, unsigned short readLength)
{
  pcap_pkthdr packetHeader;

  packetHeader.tv_sec = local_time.unixTime;
  packetHeader.tv_usec = local_time.milisecond + millis() - local_time.lastMillis;
  packetHeader.caplen = readLength;
  packetHeader.len = readLength;

  // write of wireshark head
  dataFile.write((unsigned char*) &packetHeader, sizeof(packetHeader));
  dataFile.flush();

  // write data
  dataFile.write( serial_buffer, readLength);
  dataFile.flush();
}
// -----------------------------------------------------------------------------


// store/read time to/from EEPROM
// if first bytes in EEPROM is 'DT' I suppose is it correct
void timeEEPROM(bool timeStore)
{
  if( timeStore )
  {
    // every 5 minute write to EEPROM
    if(( local_time.second == 0 )
    && (( local_time.minute % DT_STORE_MINUTE ) == 0))
    {
      EEPROM[0] = DT_MARK0;
      EEPROM[1] = DT_MARK1;
      for(unsigned int i=0; i<sizeof(local_time); i++)
      {
        EEPROM[i+2] = ((unsigned char*)&local_time)[i];
      }
    }
  }
  else
  {
    // read from EEPROM (if contain DT mark)
    if(( EEPROM[0] == DT_MARK0 )
    && ( EEPROM[1] == DT_MARK1 ))
    {
      for(unsigned int i=0; i<sizeof(local_time); i++)
      {
        ((unsigned char*)&local_time)[i] = EEPROM[i+2];
      }
    }
    else
    { // damage that store it
      EEPROM[0] = DT_MARK0;
      EEPROM[1] = DT_MARK1;
      for(unsigned int i=0; i<sizeof(local_time); i++)
      {
        EEPROM[i+2] = ((unsigned char*)&local_time)[i];
      }
    }
  }
}
// -----------------------------------------------------------------------------


// add second (when change it) and return true if do it
bool timeCounter()
{
   unsigned char days;
   unsigned long actualMillis =  millis();
   unsigned long diffMillis = actualMillis - local_time.lastMillis;
   
   // added second
   if((diffMillis > COUNT_SECOND)
   || (local_time.lastMillis > actualMillis))    // rollover (1 every 50 days)
   {
      // how many seconds add
      if(local_time.lastMillis <= actualMillis)
      {
         local_time.second += diffMillis / COUNT_SECOND;
         local_time.unixTime += diffMillis / COUNT_SECOND;
         local_time.milisecond = diffMillis % COUNT_SECOND;
      }
      else 
      {
         // rollover
         local_time.second++;
         local_time.unixTime++;
         local_time.milisecond = 0;
      }

      local_time.lastMillis = actualMillis - local_time.milisecond;
      local_time.change_Second = true;

      // overflow minute, hour, day, month, year
      if( local_time.second >= 60 )
      {
        local_time.second -= 60;
        local_time.minute++;
        local_time.change_Minute = true;
        // time shift
        local_time.lastMillis += local_time.leap;
        
        if( local_time.minute >= 60 )
        {
          local_time.minute -= 60;
          local_time.hour++;
          local_time.change_Hour = true;
          
          if( local_time.hour >= 24 )
          {
            local_time.hour -= 24;
            local_time.day++;
            local_time.change_Date = true;

            days = monthDays[ local_time.month ];
            // leap year
            if(( local_time.month == 2 )
            && !(local_time.year % 4))
              days++;

            if( local_time.day > days )
            {
              local_time.day = 1;
              local_time.month++;

              if( local_time.month >= 12 )
              {
                local_time.month = 1;
                local_time.year++;
              } // month
            } // day
            
          } // hour
        } // minute
      } // second      
      return true;
   }

   return false;
}
// -----------------------------------------------------------------------------


void tftHomeScreen()
{
  tft.fillScreen(BLACK);

  tft.setTextColor(YELLOW);
  tft.setTextSize(2);
  tft.setCursor(9, 3);
  tft.print(F("GPRS traffic logger"));

  // copyright
  tft.setTextColor(BLUE);
  tft.setTextSize(1);
  tft.setCursor(2, 310);
  tft.print(F("Software by Zdeno Sekerak (c)2016, v0.2"));
}
// -----------------------------------------------------------------------------

void tftClearText(unsigned char x, unsigned char y, unsigned char text_size, unsigned char ind, unsigned char count)
{
    tft.setTextSize(text_size);
    x += ind * text_size * FONT_WIDTH;
    tft.fillRect(x, y, count * text_size * FONT_WIDTH, text_size * FONT_HEIGHT, BLACK);
    tft.setCursor(x, y);
}
// -----------------------------------------------------------------------------

void timeShowClock(short y)
{
  char clock_buffer[3];
  
  // date
  if( local_time.change_Date )
  {
    char monthNames[][10] = {
      "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    
    local_time.change_Date = false;

    tftClearText(20, y, 3, 0, 11);
    tft.setTextColor(WHITE);

    tft.print( printDigits( local_time.day, clock_buffer));
    tft.print(".");
    tft.print( monthNames[ local_time.month ] );              // format abbr. (Jun)
//  tft.print( printDigits( local_time.month, clock_buffer)); // format DD (06)
    tft.print(".");
    tft.print( local_time.year);
  }

  // change hour
  if( local_time.change_Hour )
  {
    local_time.change_Hour = false;

    tftClearText(23, 40+y, 4, 0, 3);
    tft.setTextColor(WHITE);
    tft.print( printDigits( local_time.hour, clock_buffer));
    tft.print(":");
  }

  // change minute
  if( local_time.change_Minute )
  {
    local_time.change_Minute = false;
    
    tftClearText(23, 40+y, 4, 3, 3);
    tft.setTextColor(WHITE);
    tft.print( printDigits( local_time.minute, clock_buffer));
    tft.print(":");
  }

  // change second
  if( local_time.change_Second )
  {
    local_time.change_Second = false;

    tftClearText(23, 40+y, 4, 6, 2);
    tft.setTextColor(WHITE);
    tft.print( printDigits( local_time.second, clock_buffer));
  }
}
// -----------------------------------------------------------------------------


// show actual filename on display
void sdShowFileName(short y, char* log_file)
{
  tft.setCursor(5, 1+y);
  tft.setTextColor(WHITE);
  tft.setTextSize(2);

  tft.fillRect(1, y, tft.width()-2, 2*FONT_HEIGHT, BLACK);
  if( !dataFile )
    tft.print("SD card isn't avail");
  else
  {
    log_file += LOG_SUBDIR_IND - 1;
    tft.print(log_file);
  }
}
// -----------------------------------------------------------------------------


// get number from char presentation
byte atoi2(const char* buffer)
{
  if( isAlphaNumeric(buffer[0]))
      return (buffer[0] - '0') * 10 + buffer[1] - '0';

  return buffer[1] - '0';
}
// -----------------------------------------------------------------------------


// utility function for digital clock display: prints preceding colon and leading 0
// buffer must have size 4 Bytes
char* printDigits(byte digits, char* buffer)
{
  if(digits < 10)
  {
    buffer[0] = '0';
    buffer[1] = '0' + digits;
  }
  else
  {
    buffer[0] = '0' + int(digits / 10);
    buffer[1] = '0' + int(digits % 10);
  }
  buffer[2] = '\0';
  return buffer;
}
// -----------------------------------------------------------------------------


void terminalInit()
{
  // terminal
  tft.fillRect(1, LOG_Y, tft.width()-2, LOG_HEIGHT+1, BLACK);
  tft.drawRect(0, LOG_Y, tft.width(), LOG_HEIGHT+2, WHITE);
  tft.setCursor(0, LOG_Y+1);

  terminal.X = tft.getCursorX();
  terminal.Y = tft.getCursorY();
  terminal.clearY = LOG_Y + LOG_HEIGHT + 1;
}
// -----------------------------------------------------------------------------


// clear partial lines
void terminalClear()
{
  // dalsim znakom spadne na dalsi riadok
  if(tft.getCursorX() >= (tft.width() - FONT_WIDTH))
     tft.println();

  // skoncil na stranke
  if(tft.getCursorY() > (LOG_Y + LOG_HEIGHT))
  {
    tft.setCursor(0, LOG_Y+1);

    terminal.X = tft.getCursorX();
    terminal.Y = tft.getCursorY();
    terminal.clearY = terminal.Y;
  }

  // podmaz, nepodmazane riadky pod nim
  if(tft.getCursorY() >= terminal.clearY)
  {
    tft.fillRect(1, terminal.clearY, tft.width()-2, FONT_HEIGHT, BLACK);
    terminal.clearY += FONT_HEIGHT;
    
    if(terminal.clearY <= (LOG_Y + LOG_HEIGHT))
      tft.drawFastHLine(1, terminal.clearY, tft.width()-2, YELLOW);
  }
}
// -----------------------------------------------------------------------------


void terminalShow(char *readBytes, unsigned short readLength)
{
  byte i;

  tft.setCursor(terminal.X, terminal.Y);
  tft.setTextColor(WHITE);
  tft.setTextSize(1);

  for (i = 0; i < readLength; i++)
  {
    if ( readBytes[i] < 0x20 )
    {
      tft.print(' ');
      if ( readBytes[i] == '\n')
        tft.println();
    }
    else
      tft.print(readBytes[i]);

    terminalClear();
  }

  terminal.X = tft.getCursorX();
  terminal.Y = tft.getCursorY();
}
// -----------------------------------------------------------------------------

