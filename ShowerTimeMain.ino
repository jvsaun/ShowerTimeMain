



#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>

constexpr uint8_t RST_PIN = 9;
constexpr uint8_t SS_PIN = 10;

byte sensorInterrupt = 0;  // 0 = digital pin 2
byte sensorPin       = 2;

// The hall-effect flow sensor outputs approximately 4.5 pulses per second per
// litre/minute of flow.
float calibrationFactor = 4.5;

volatile byte pulseCount;

int solenoidPin = 4;

float flowRate;
unsigned int flowMilliLitres;
unsigned long totalMilliLitres;
float totalGallons;
float remainingGallons;
float gallons;
int currentBalance;
unsigned long oldTime;
unsigned int loggedIn;
int32_t balance;
int errorCount = 0;

MFRC522 mfrc522(SS_PIN, RST_PIN);  // Create MFRC522 instance

MFRC522::MIFARE_Key key;

LiquidCrystal_I2C lcd (0x27, 2, 1, 0, 4, 5, 6, 7, 3, POSITIVE);

void setup()

{
  Serial.begin(9600);    // Initialize serial communications with the PC
  while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();      // Init SPI bus
  mfrc522.PCD_Init();   // Init MFRC522
  mfrc522.PCD_DumpVersionToSerial();  // Show details of PCD - MFRC522 Card Reader details
  Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));
  // Prepare the key (used both as key A and as key B)
  // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }

  Serial.println(F("Scan a MIFARE Classic PICC to demonstrate Value Block mode."));
  Serial.print(F("Using key (for A and B):"));
  dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);
  Serial.println();

  Serial.println(F("BEWARE: Data will be written to the PICC, in sector #1"));
  pinMode(sensorPin, INPUT);
  digitalWrite(sensorPin, HIGH);

  pinMode(solenoidPin, OUTPUT);           //Sets the pin as an output

  pulseCount        = 0;
  flowRate          = 0.0;
  flowMilliLitres   = 0;
  totalMilliLitres  = 0;
  totalGallons      = 0.0;
  oldTime           = 0;
  remainingGallons  = 21.0;
  loggedIn          = 0;
  currentBalance    = 0;

  // The Hall-effect sensor is connected to pin 2 which uses interrupt 0.
  // Configured to trigger on a FALLING state change (transition from HIGH
  // state to LOW state)
  attachInterrupt(sensorInterrupt, pulseCounter, FALLING);
  displayIdle();
}

void loop()

{
  Serial.println(errorCount);
  if (loggedIn == 1 )
  {
    authenticateCard(); // check if card is still available, if not log out
    checkBalance(); //get current balance from card
    displayBalance();
    getFlow(); // get new water usage from last second
    writeBalance(); // write the remaining balance to card
  }

  if ( ! mfrc522.PICC_IsNewCardPresent())
  {
    return;
  }

  if ( ! mfrc522.PICC_ReadCardSerial())
  {
    return;
  }
  Serial.println("First Authentication");
  authenticateCard();

}

void authenticateCard()
{
// Show some details of the PICC (that is: the tag/card)
  Serial.print(F("Card UID:"));
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();
  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));

  // Check for compatibility
  if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
          &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
          &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println(F("This sample only works with MIFARE Classic cards."));
    //logOut();
    errorCount ++;
    return;
  }

  // In this sample we use the second sector,
  // that is: sector #1, covering block #4 up to and including block #7
  byte sector         = 1;
  byte valueBlockA    = 5;
  byte valueBlockB    = 6;
  byte trailerBlock   = 7;
  MFRC522::StatusCode status;
  byte buffer[18];
  byte size = sizeof(buffer);

  // Authenticate using key A
  Serial.println(F("Authenticating using key A..."));
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    //logOut();
    errorCount ++;
    return;
  }

  // Show the whole sector as it currently is
  Serial.println(F("Current data in sector:"));
  mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
  Serial.println();

  // We need a sector trailer that defines blocks 5 and 6 as Value Blocks and enables key B
  // The last block in a sector (block #3 for Mifare Classic 1K) is the Sector Trailer.
  // See http://www.nxp.com/documents/data_sheet/MF1S503x.pdf sections 8.6 and 8.7:
  //      Bytes 0-5:   Key A
  //      Bytes 6-8:   Access Bits
  //      Bytes 9:     User data
  //      Bytes 10-15: Key B (or user data)
  byte trailerBuffer[] = {
    255, 255, 255, 255, 255, 255,       // Keep default key A
    0, 0, 0,
    0,
    255, 255, 255, 255, 255, 255
  };

  mfrc522.MIFARE_SetAccessBits(&trailerBuffer[6], 0, 6, 6, 3);

  // Read the sector trailer as it is currently stored on the PICC
  Serial.println(F("Reading sector trailer..."));
  status = mfrc522.MIFARE_Read(trailerBlock, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    //logOut();
    errorCount ++;
    return;
  }
  // Check if it matches the desired access pattern already;
  // because if it does, we don't need to write it again...
  if (    buffer[6] != trailerBuffer[6]
          ||  buffer[7] != trailerBuffer[7]
          ||  buffer[8] != trailerBuffer[8]) {
    // They don't match (yet), so write it to the PICC
    Serial.println(F("Writing new sector trailer..."));
    status = mfrc522.MIFARE_Write(trailerBlock, trailerBuffer, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Write() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      //logOut();
      errorCount ++;
      return;
    }
  }

  // Authenticate using key B
  Serial.println(F("Authenticating again using key B..."));
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    //logOut();
    errorCount ++;
    return;
  }

  // A value block has a 32 bit signed value stored three times
  // and an 8 bit address stored 4 times. Make sure that valueBlockA
  // and valueBlockB have that format (note that it will only format
  // the block when it doesn't comply to the expected format already).
  formatValueBlock(valueBlockA);
  formatValueBlock(valueBlockB);

  // If we got to this point without error, log in!
  logIn(); 
}

void logIn()
// log in procedure
{
// jim added
    loggedIn          = 1;

  checkBalance();
  valveOn();
}

void logOut()
// log out procedure
{
  Serial.print(F("Logging Out"));
  valveOff();
  loggedIn = 0;
  displayIdle();
}


void checkBalance()
{
    MFRC522::StatusCode status;
  byte sector         = 1;
  byte valueBlockA    = 5;
  byte valueBlockB    = 6;
  byte trailerBlock   = 7;
  // Show the new value of valueBlockB
  status = mfrc522.MIFARE_GetValue(valueBlockB, &balance);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("mifare_GetValue() failed: "));
    Serial.println("CheckBalance Fail");
    Serial.println(mfrc522.GetStatusCodeName(status));
    //logOut();
    errorCount ++;
    return;
  }
  Serial.println("Balance is:");
  Serial.println(balance);
  
}

void displayBalance()
// Show balance on LCD
{
  lcd.begin(16, 2);
  lcd.clear();
  lcd.print("WATER REMAINING");
  lcd.setCursor(0, 1);
  lcd.print(balance);
}

void writeBalance(){
// write new balance to card
  MFRC522::StatusCode status;
  byte sector         = 1;
  byte valueBlockA    = 5;
  byte valueBlockB    = 6;
  byte trailerBlock   = 7;

  status = mfrc522.MIFARE_SetValue(valueBlockB, balance);

  //status = mfrc522.MIFARE_SetValue(valueBlockB, 10000);
  
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print(F("mifare_SetValue() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    //logOut();
    errorCount ++;
    return;
  }
}

void valveOff()
{
  digitalWrite(solenoidPin, HIGH);
}

void valveOn()

{
  digitalWrite(solenoidPin, LOW);
}

void pulseCounter()
// Increment the pulse counter
{
  pulseCount++;
}

void displayIdle()
// Display Idle Message
{
  lcd.begin(16, 2);
  lcd.clear();
  lcd.print("CONSERVE WATER");
  lcd.setCursor(0, 1);
  lcd.print("SHOWER WITH FRIEND");
}

void displayOutOfWater()
// Display Idle Message
{
  lcd.begin(16, 2);
  lcd.clear();
  lcd.print("OUT OF WATER!");
  delay(1500);
}

void getFlow()
{
  if ((millis() - oldTime) > 1000)   // Only process counters once per second
  {
    // Disable the interrupt while calculating flow rate and sending the value to
    // the host
    detachInterrupt(sensorInterrupt);

    // Because this loop may not complete in exactly 1 second intervals we calculate
    // the number of milliseconds that have passed since the last execution and use
    // that to scale the output. We also apply the calibrationFactor to scale the output
    // based on the number of pulses per second per units of measure (litres/minute in
    // this case) coming from the sensor.
    flowRate = ((1000.0 / (millis() - oldTime)) * pulseCount) / calibrationFactor;

    // Note the time this processing pass was executed. Note that because we've
    // disabled interrupts the millis() function won't actually be incrementing right
    // at this point, but it will still return the value it was set to just before
    // interrupts went away.
    oldTime = millis();

    // Divide the flow rate in litres/minute by 60 to determine how many litres have
    // passed through the sensor in this 1 second interval, then multiply by 1000 to
    // convert to millilitres.
    flowMilliLitres = (flowRate / 60) * 1000;
    // Add the millilitres passed in this second to the cumulative total
    totalMilliLitres += flowMilliLitres;
    Serial.print("Flow ML: ");
    Serial.println(flowMilliLitres);
    balance -= flowMilliLitres / 10;
    Serial.print("CL balance = ");
    Serial.println(balance);
    Serial.print("ML Used = ");
    Serial.println(totalMilliLitres);
   
    unsigned int frac;

    // Print the flow rate for this second in litres / minute
    Serial.print("Flow rate: ");
    Serial.print(int(flowRate));  // Print the integer part of the variable
    Serial.print(".");             // Print the decimal point
    // Determine the fractional part. The 10 multiplier gives us 1 decimal place.
    frac = (flowRate - int(flowRate)) * 10;
    Serial.print(frac, DEC) ;      // Print the fractional part of the variable
    Serial.print("L/min");
    // Print the number of litres flowed in this second
    Serial.print("  Current Liquid Flowing: ");             // Output separator
    Serial.print(flowMilliLitres);
    Serial.print("mL/Sec");

    // Print the cumulative total of litres flowed since starting
    Serial.print("  Output Liquid Quantity: ");             // Output separator
    Serial.print(totalMilliLitres);
    Serial.println("mL");

    // Print the cumulative total of litres flowed since starting
    Serial.print("  Output Liquid Quantity: ");             // Output separator
    Serial.print(totalGallons);
    Serial.println(" Gallons");
    // Reset the pulse counter so we can start incrementing again
    pulseCount = 0;

    // Enable the interrupt again now that we've finished sending output
    attachInterrupt(sensorInterrupt, pulseCounter, FALLING);
  }
}

/**
* Helper routine to dump a byte array as hex values to Serial.
*/
void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}

/**
 * Ensure that a given block is formatted as a Value Block.
 */
void formatValueBlock(byte blockAddr) {
  byte buffer[18];
  byte size = sizeof(buffer);
  MFRC522::StatusCode status;

  Serial.print(F("Reading block ")); Serial.println(blockAddr);
  status = mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  if (    (buffer[0] == (byte)~buffer[4])
          &&  (buffer[1] == (byte)~buffer[5])
          &&  (buffer[2] == (byte)~buffer[6])
          &&  (buffer[3] == (byte)~buffer[7])

          &&  (buffer[0] == buffer[8])
          &&  (buffer[1] == buffer[9])
          &&  (buffer[2] == buffer[10])
          &&  (buffer[3] == buffer[11])

          &&  (buffer[12] == (byte)~buffer[13])
          &&  (buffer[12] ==        buffer[14])
          &&  (buffer[12] == (byte)~buffer[15])) {
    Serial.println(F("Block has correct Value Block format."));
  }
  else {
    Serial.println(F("Formatting as Value Block..."));
    byte valueBlock[] = {
      0, 0, 0, 0,
      255, 255, 255, 255,
      0, 0, 0, 0,
      blockAddr, ~blockAddr, blockAddr, ~blockAddr
    };
    status = mfrc522.MIFARE_Write(blockAddr, valueBlock, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Write() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
    }
  }
}


