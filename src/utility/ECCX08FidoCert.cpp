/*
  This file is part of the ArduinoECCX08 library.
  Copyright (c) 2019 Arduino SA. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "ArduinoECCX08.h"

extern "C" {
  #include "sha1.h"
}
#include "ASN1Utils.h"
#include "PEMUtils.h"

#include "ECCX08FidoCert.h"

struct __attribute__((__packed__)) CompressedCert {
  uint8_t signature[64];
  struct {
    uint8_t year:5;
    uint8_t month:4;
    uint8_t day:5;
    uint8_t hour:5;
    uint8_t expires:5;
  } dates;
  uint8_t unused[5];
};

static const uint8_t DEFAULT_SERIAL_NUMBER[] = { 0x01 };

ECCX08FidoCertClass::ECCX08FidoCertClass() :
  _serialNumber(DEFAULT_SERIAL_NUMBER),
  _serialNumberLength(sizeof(DEFAULT_SERIAL_NUMBER)),
  _bytes(NULL),
  _length(0)
{
}

ECCX08FidoCertClass::~ECCX08FidoCertClass()
{
  if (_bytes) {
    free(_bytes);
    _bytes = NULL;
  }
}

int ECCX08FidoCertClass::beginStorage(int keySlot, int issuerKeySlot)
{
  if (keySlot < 0 || keySlot > 8) {
    return 0;
  }
  if (issuerKeySlot < 0 || issuerKeySlot > 8) {
    return 0;
  }

  _keySlot = keySlot;
  _issuerKeySlot = issuerKeySlot;

  return 1;
}

int ECCX08FidoCertClass::endStorage(uint8_t **pp_der)
{
  if (!buildCert(true)) {
    return -1;
  }

//  return PEMUtils.base64Encode(_bytes, _length, "-----BEGIN CERTIFICATE-----\n", "\n-----END CERTIFICATE-----\n");
  *pp_der = _bytes;
  return _length;
}

int ECCX08FidoCertClass::beginReconstruction(int keySlot, int issuerKeySlot)
{
  if (keySlot < 0 || keySlot > 8) {
    return 0;
  }
  if (issuerKeySlot < 0 || issuerKeySlot > 8) {
    return 0;
  }

  _keySlot = keySlot;
  _issuerKeySlot = issuerKeySlot;

  return 1;
}

int ECCX08FidoCertClass::endReconstruction()
{
  if (!buildCert(false)) {
    return 0;
  }

  return 1;
}

uint8_t* ECCX08FidoCertClass::bytes()
{
  return _bytes;
}

int ECCX08FidoCertClass::length()
{
  return _length;
}

String ECCX08FidoCertClass::sha1()
{
  char result[20 + 1];

//  SHA1(result, (const char*)_bytes, _length);
  internal_SHA1(result, (const char*)_bytes, _length);

  String sha1Str;

  sha1Str.reserve(40);

  for (int i = 0; i < 20; i++) {
    uint8_t b = result[i];

    if (b < 16) {
      sha1Str += '0';
    }
    sha1Str += String(b, HEX);
  }

  return sha1Str;
}

void ECCX08FidoCertClass::setIssueYear(int issueYear)
{
  struct CompressedCert* compressedCert = (struct CompressedCert*)_temp;

  compressedCert->dates.year = (issueYear - 2000);
}

void ECCX08FidoCertClass::setIssueMonth(int issueMonth)
{
  struct CompressedCert* compressedCert = (struct CompressedCert*)_temp;

  compressedCert->dates.month = issueMonth;
}

void ECCX08FidoCertClass::setIssueDay(int issueDay)
{
  struct CompressedCert* compressedCert = (struct CompressedCert*)_temp;

  compressedCert->dates.day = issueDay;
}

void ECCX08FidoCertClass::setIssueHour(int issueHour)
{
  struct CompressedCert* compressedCert = (struct CompressedCert*)_temp;

  compressedCert->dates.hour = issueHour;
}

void ECCX08FidoCertClass::setExpireYears(int expireYears)
{
  struct CompressedCert* compressedCert = (struct CompressedCert*)_temp;

  compressedCert->dates.expires = expireYears;
}

void ECCX08FidoCertClass::setSerialNumber(const byte serialNumber[], int length)
{
  _serialNumber = serialNumber;
  _serialNumberLength = length;
}

void ECCX08FidoCertClass::setCountryName(const char *countryName)
{
  _countryName = countryName;
}

void ECCX08FidoCertClass::setStateProvinceName(const char* stateProvinceName)
{
  _stateProvinceName = stateProvinceName;
}

void ECCX08FidoCertClass::setLocalityName(const char* localityName)
{
  _localityName = localityName;
}

void ECCX08FidoCertClass::setOrganizationName(const char* organizationName)
{
  _organizationName = organizationName;
}

void ECCX08FidoCertClass::setOrganizationalUnitName(const char* organizationalUnitName)
{
  _organizationalUnitName = organizationalUnitName;
}

void ECCX08FidoCertClass::setCommonName(const char* commonName)
{
  _commonName = commonName;
}

void ECCX08FidoCertClass::setIssuerName(const char* issuerName)
{
  _issuerName = issuerName;
}

int ECCX08FidoCertClass::buildCert(bool buildSignature)
{
  uint8_t publicKey[64];

  if (!ECCX08.generatePublicKey(_keySlot, publicKey)) {
    return 0;
  }

  int certInfoLen = certInfoLength();
  int certInfoHeaderLen = ASN1Utils.sequenceHeaderLength(certInfoLen);

  uint8_t certInfo[certInfoLen + certInfoHeaderLen];

  appendCertInfo(publicKey, certInfo, certInfoLen);
  
  if (buildSignature) {
    byte certInfoSha256[64];

    memset(certInfoSha256, 0x00, sizeof(certInfoSha256));

    if (!ECCX08.beginSHA256()) {
      return 0;
    }

    for (int i = 0; i < (certInfoHeaderLen + certInfoLen); i += 64) {
      int chunkLength = (certInfoHeaderLen + certInfoLen) - i;

      if (chunkLength > 64) {
        chunkLength = 64;
      }

      if (chunkLength == 64) {
        if (!ECCX08.updateSHA256(&certInfo[i])) {
          return 0;
        }
      } else {
        if (!ECCX08.endSHA256(&certInfo[i], chunkLength, certInfoSha256)) {
          return 0;
        }
      }
    }

    if (!ECCX08.ecSign(_issuerKeySlot, certInfoSha256, _temp)) {
      return 0;
    }

    // if (!ECCX08.writeSlot(_dateAndSignatureSlot, _temp, sizeof(_temp))) {
    //   return 0;
    // }
  }

  int signatureLen = ASN1Utils.signatureLength(_temp);

  int certDataLen = certInfoLen + certInfoHeaderLen + signatureLen;
  int certDataHeaderLen = ASN1Utils.sequenceHeaderLength(certDataLen);

  _length = certDataLen + certDataHeaderLen;
  _bytes = (byte*)realloc(_bytes, _length);

  if (!_bytes) {
    _length = 0;
    return 0;
  }

  uint8_t* out = _bytes;

  out += ASN1Utils.appendSequenceHeader(certDataLen, out);

  memcpy(out, certInfo, certInfoHeaderLen + certInfoLen);
  out += (certInfoHeaderLen + certInfoLen);

  // signature
  out += ASN1Utils.appendSignature(_temp, out);

  return 1;
}

int ECCX08FidoCertClass::certInfoLength()
{
  struct CompressedCert* compressedCert = (struct CompressedCert*)_temp;

  int year = (compressedCert->dates.year + 2000);
  int expireYears = compressedCert->dates.expires;

  int datesSize = 30;

  if (year > 2049) {
    // two more bytes for GeneralizedTime
    datesSize += 2;
  }

  if ((year + expireYears) > 2049) {
    // two more bytes for GeneralizedTime
    datesSize += 2;
  }

  int serialNumberLen = ASN1Utils.serialNumberLength(_serialNumber, _serialNumberLength);

  int issuerAndSubjectLen = ASN1Utils.issuerOrSubjectLength(_countryName,
                                                            _stateProvinceName,
                                                            _localityName,
                                                            _organizationName,
                                                            _organizationalUnitName,
                                                            _commonName);

  int issuerAndSubjectHeaderLen = ASN1Utils.sequenceHeaderLength(issuerAndSubjectLen);

  int issuerLen = ASN1Utils.issuerOrSubjectLength(_countryName,
                                                            _stateProvinceName,
                                                            _localityName,
                                                            _organizationName,
                                                            _organizationalUnitName,
                                                            _issuerName);

  int issuerHeaderLen = ASN1Utils.sequenceHeaderLength(issuerLen);


  int publicKeyLen = ASN1Utils.publicKeyLength();
  
  int fidoU2fExtentionLen = ASN1Utils.fidoU2fExtensionLength();
  int fidoU2fExtentionHeaderLen = ASN1Utils.sequenceHeaderLength(fidoU2fExtentionLen);

  int certInfoLen = 5 + serialNumberLen + 12 + 
                    issuerAndSubjectHeaderLen + issuerAndSubjectLen + 
                    issuerHeaderLen + issuerLen + 
                    (datesSize + 2) + publicKeyLen +
                    fidoU2fExtentionHeaderLen + fidoU2fExtentionLen;

  return certInfoLen;
}

void ECCX08FidoCertClass::appendCertInfo(uint8_t publicKey[], uint8_t buffer[], int length)
{
  struct CompressedCert* compressedCert = (struct CompressedCert*)_temp;
  uint8_t* out = buffer;

  // dates
  int year = (compressedCert->dates.year + 2000);
  int month = compressedCert->dates.month;
  int day = compressedCert->dates.day;
  int hour = compressedCert->dates.hour;
  int expireYears = compressedCert->dates.expires;

  out += ASN1Utils.appendSequenceHeader(length, out);

  // version
  *out++ = 0xA0;
  *out++ = 0x03;
  *out++ = 0x02;
  *out++ = 0x01;
  *out++ = 0x02;

  // serial number
  out += ASN1Utils.appendSerialNumber(_serialNumber, _serialNumberLength, out);

  out += ASN1Utils.appendEcdsaWithSHA256(out);

  // issuer
  int issuerLen = ASN1Utils.issuerOrSubjectLength(_countryName,
                                                            _stateProvinceName,
                                                            _localityName,
                                                            _organizationName,
                                                            _organizationalUnitName,
                                                            _issuerName);

  out += ASN1Utils.appendSequenceHeader(issuerLen, out);
  ASN1Utils.appendIssuerOrSubject(_countryName,
                                  _stateProvinceName,
                                  _localityName,
                                  _organizationName,
                                  _organizationalUnitName,
                                  _issuerName, out);
  out += issuerLen;

  *out++ = ASN1_SEQUENCE;
  *out++ = 30 + ((year > 2049) ? 2 : 0) + (((year + expireYears) > 2049) ? 2 : 0);
  out += ASN1Utils.appendDate(year, month, day, hour, 0, 0, out);
  out += ASN1Utils.appendDate(year + expireYears, month, day, hour, 0, 0, out);

  // subject
  int issuerAndSubjectLen = ASN1Utils.issuerOrSubjectLength(_countryName,
                                                            _stateProvinceName,
                                                            _localityName,
                                                            _organizationName,
                                                            _organizationalUnitName,
                                                            _commonName);
  out += ASN1Utils.appendSequenceHeader(issuerAndSubjectLen, out);
  ASN1Utils.appendIssuerOrSubject(_countryName,
                                  _stateProvinceName,
                                  _localityName,
                                  _organizationName,
                                  _organizationalUnitName,
                                  _commonName, out);
  out += issuerAndSubjectLen;

  // public key
  out += ASN1Utils.appendPublicKey(publicKey, out);

  // FidoU2fExtention
  int fidoU2fExtentionLen = ASN1Utils.fidoU2fExtensionLength();
  out += ASN1Utils.appendExtensionHeader(fidoU2fExtentionLen, out);
  ASN1Utils.appendFidoU2fExtension(publicKey, out);
  out += fidoU2fExtentionLen;
}

ECCX08FidoCertClass ECCX08Cert;
