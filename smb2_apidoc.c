/*********************  P r o g r a m  -  M o d u l e ***********************/
/*!
 *        \file  smb2_apidoc.c
 *
 *      \author  dieter.pfeuffer@men.de
 *        $Date: 2009/07/31 17:25:31 $
 *    $Revision: 1.3 $
 *
 *      \brief   User documentation for SMB2_API
 *
 *     Required: -
 *
 *     \switches -
 */
 /*-------------------------------[ History ]--------------------------------
 *
 * $Log: smb2_apidoc.c,v $
 * Revision 1.3  2009/07/31 17:25:31  MRoth
 * R: new smb2_boardident tool
 * M: added smb2_boardident tool to description and examples section
 *
 * Revision 1.2  2009/06/22 11:59:32  dpfeuffer
 * R:1.a: Porting to MIDS5
 * M:1.a) MDIS4 renamed to MDIS5
 *     b) Note for MDIS4 compatibility added
 *
 * Revision 1.1  2006/02/28 15:57:44  DPfeuffer
 * Initial Revision
 *
 *---------------------------------------------------------------------------
 * (c) Copyright 2006 by MEN Mikro Elektronik GmbH, Nuernberg, Germany
 ****************************************************************************/

/*! \mainpage

  This document describes the SMB2_API features of the SMB2 MDIS5 driver,
  a generic driver for SMBus devices (e.g. EEPROMS).

  The software package consists of the SMB2 MDIS5 driver, the SMB2_API C library
  and example applications (SMB2_SIMP, SMB2_CTRL, SMB2_BOARDIDENT see Examples section).

  Note: MDIS5 32bit drivers are compatible to the MDIS4 drivers but must not
        be mixed with MDIS4 drivers at one target system.\n\n

  \section FuncOv Functional Overview

  \n
  <H2>!!! Please be careful when you write to SMBus devices. !!!</H2>
  <H2>!!! Otherwise you may destroy important data (e.g. on EEPROMs)
  or you may cause damage to the HW. !!!</H2>
  \n

  The SMB2_API library provides user mode applications access to devices on
  a SMBus. The library uses internal the MDIS_API to communicate with the
  MDIS5 SMB2 driver. The SMB2 driver uses the SMB2 kernel mode library supplied
  by a BBIS board driver or a BSP to control a individual SMBus controller.
  \ref _smb2_swmodules

  SMB2_API reflects the SMB2 library functions via the SMB2 MDIS5 driver to user
  mode applications. The SMB2_API library must be initialized with SMB2API_Init()
  and deinitialized with SMB2API_Exit(). The SMB2API_Errstring() function converts
  an SMB2 error code (\ref _SMB2_ERR) or MDIS error code into an error message string.

  The main features of the SMB2_API are:

  <b>Single read/write</b>\n
  - Write/Read one data byte SMB2API_WriteByte(), SMB2API_ReadByte()
  - Write command and write/read one data byte SMB2API_WriteByteData(), SMB2API_ReadByteData()
  - Write command and write/read one data word SMB2API_WriteWordData(), SMB2API_ReadWordData()
  - Write command and one data word, then read one data word SMB2API_ProcessCall()

  <b>Block read/write</b>\n
  - Writes command and write/read a data block SMB2API_WriteBlockData(), SMB2API_ReadBlockData()
  - Write command and data block, then read data block SMB2API_BlockProcessCall()

  <b>Other read/write</b>\n
  - Quick command SMB2API_QuickComm()
  - Read/write using the I2C protocol SMB2API_I2CXfer()

  <b>Alert support</b>\n
  - Issue a read byte command to the Alert Response Address SMB2API_AlertResponse()
  - Install/remove alert callback function SMB2API_AlertCbInstall(), SMB2API_AlertCbInstallSig(), SMB2API_AlertCbRemove()

  <b>Unsupported SMB2 library functions</b>\n
  - SMB2API_SmbXfer()\n

  \n \subsection smb2_api_call   Calling SMB2_API functions
  The SMB2_API functions can be called either directly or via the SMB-Handle
  (see #SMB_ENTRIES struct):

  Calling a SMB2_API function directly, example:
  \verbatim

  err = SMB2API_ReadByte( smbHdl, 0x00, addr, &byte ); \endverbatim

  \n
  Calling a SMB2_API function over the SMB-Handle.
  This simplifies to port kernel mode software to user mode software modules. Example:

  \verbatim

  err = ((SMB_HANDLE*)smbHdl)->ReadByte( smbHdl, 0x00, addr, &byte ); \endverbatim
  \n

  \n \section descriptor_entries SMB2 Driver Descriptor Entries
  \n

    The low-level driver initialization routine decodes the following entries
    ("keys") in addition to the general descriptor keys:

    <table border="0">
    <tr><td><b>Descriptor entry</b></td>
        <td><b>Description</b></td>
        <td><b>Values</b></td>
    </tr>
    <tr><td>SMB_BUSNBR</td>
        <td>SMBus bus number</td>
        <td>0..n\n
			Default: none</td>
    </tr>
    </tr>
    <tr><td>SMB_DEVS_ONLY</td>
        <td>Array of only allowed SMB device addresses (all addresses if not set)</td>
        <td>0x00..0xff,0x00..0xff,..\n
			Default: none</td>
    </tr>
    </table>

    \n \subsection smb2_min   Minimum descriptor
    smb2_min.dsc (see Examples section)\n
    Demonstrates the minimum set of options necessary for using the driver.

    \n \subsection smb2_max   Maximum descriptor
    smb2_max.dsc (see Examples section)\n
    Shows all possible configuration options for this driver.
*/

/***************************************************************************/
/*! \page _smb2_swmodules SMB2 Software Module Structure

  The following image shows the structure of the SMB2 software modules. A user
  application can access a SMBus device via the HW independent SMB2_API library.
  The SMB2 driver is also HW independent. The SMB2 kernel mode library encapsulates
  the HW specific control of an individual SMBus controller.\n\n

  \smb2_structure

 */

/** \example smb2_simp.c */
/** \example smb2_f601.c */
/** \example smb2_ctrl.c */
/** \example smb2_boardident.c */
/** \example smb2api.c */
/** \example smb2_min.dsc */
/** \example smb2_max.dsc */

/*! \page dummy

 \menimages

*/