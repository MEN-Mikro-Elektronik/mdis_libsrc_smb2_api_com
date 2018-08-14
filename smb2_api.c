/*********************  P r o g r a m  -  M o d u l e ***********************/
/*!
 *        \file  smb2_api.c
 *
 *      \author  dieter.pfeuffer@men.de
 *        $Date: 2010/04/19 13:42:16 $
 *    $Revision: 1.9 $
 *
 *  	 \brief  API functions to access the SMB2 MDIS driver
 *
 *     Switches: -
 */
/*-------------------------------[ History ]---------------------------------
 *
 * $Log: smb2_api.c,v $
 * Revision 1.9  2010/04/19 13:42:16  dpfeuffer
 * R: SMB_ERR_CTRL_BUSY error code was added to smb2.h (but not added here)
 * M: missing SMB_ERR_CTRL_BUSY added to SMB2API_Errstring()
 *
 * Revision 1.8  2009/06/22 11:59:30  dpfeuffer
 * R: UOS_SigInit declaration was changed
 * M: add __MAPILIB keyword to SigHandler
 *    (cosmetics, because lib uses the right calling convention)
 *
 * Revision 1.7  2007/05/15 14:31:56  JWu
 * (Empty Log Message)
 *
 * Revision 1.6  2007/02/20 15:51:03  DPfeuffer
 * SMB_ERR_NO_IDLE was missing
 * undo of VxWorks specific fix
 *
 * Revision 1.5  2006/10/05 17:40:09  cs
 * changed:
 *     - SMB2API_Exit Prototype to match changed SMB2 Lib API
 *
 * Revision 1.4  2006/05/31 08:22:26  DPfeuffer
 * - error code mapping changed
 *
 * Revision 1.3  2006/03/17 15:13:48  DPfeuffer
 * SMB2_TRANSFER and SMB2_TRANSFER_BLOCK struct: now named unions (ANSI C)
 *
 * Revision 1.2  2006/03/03 10:52:42  DPfeuffer
 * - SMB2API_Exit(): error handling fixed
 * - ERROR label replaced by ERR_EXIT
 *
 * Revision 1.1  2006/02/28 15:57:43  DPfeuffer
 * Initial Revision
 *
 *---------------------------------------------------------------------------
 * (c) Copyright 2006 by MEN mikro elektronik GmbH, Nuernberg, Germany
 ****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <MEN/men_typs.h>
#include <MEN/mdis_err.h>
#include <MEN/mdis_api.h>
#include <MEN/usr_oss.h>

#define SMB2_API_COMPILE
#include <MEN/smb2_api.h>
#include <MEN/smb2_drv.h>

/*-----------------------------------------+
|  DEFINES                                 |
+-----------------------------------------*/
#define DO_BLK_SETSTAT( obj, code ) \
{\
	M_SG_BLOCK blk;\
	blk.size = sizeof(obj);\
	blk.data = (void *)&obj;\
	rv = M_setstat( ((SMB_HANDLE*)smbHdl)->path, code, (INT32_OR_64)&blk );\
	if( rv )\
		rv = UOS_ErrnoGet();\
}

#define DO_BLK_GETSTAT( obj, code ) \
{\
	M_SG_BLOCK blk;\
	blk.size = sizeof(obj);\
	blk.data = (void *)&obj;\
	rv = M_getstat( ((SMB_HANDLE*)smbHdl)->path, code, (int32 *)&blk );\
	if( rv )\
		rv = UOS_ErrnoGet();\
}

#define SIG_FREE	0
#define SIG_USED	1

/* MDIS implementations should define at least UOS_SIG_USR1 and UOS_SIG_USR2 */
#if defined (UOS_SIG_USR1) && (UOS_SIG_USR2)
#	define LAST_SIG UOS_SIG_USR2
#else
#	error "UOS_SIG_USR1 and UOS_SIG_USR2 must be defined!"
#endif

/* some MDIS implementations defines UOS_SIG_USR3 and UOS_SIG_USR4 */
#if defined (UOS_SIG_USR3) && (UOS_SIG_USR4)
#	undef  LAST_SIG
#	define LAST_SIG UOS_SIG_USR4
#endif

/* other MDIS implementations defines UOS_SIG_MAX */
#if defined(UOS_SIG_MAX) && ((UOS_SIG_MAX) > LAST_SIG)
#	undef LAST_SIG
#	define LAST_SIG UOS_SIG_MAX
#endif

#define FIRST_SIG	UOS_SIG_USR1
#define NBR_OF_SIG	(LAST_SIG - FIRST_SIG)

/* limit to 32 signals max */
#if NBR_OF_SIG > 32
#	undef NBR_OF_SIG
#	define NBR_OF_SIG 32
#endif

/*-----------------------------------------+
|  TYPEDEFS                                |
+-----------------------------------------*/
/** Local structure for alert signals */
typedef struct
{
	u_int32		sigCode; 	/**< UOS_SIG signal code */
	u_int8		condition;	/**< signal condition (see SIG_XXX above) */
}SIGNAL;

/** Local structure for SMB_HANDLE */
typedef struct
{
	SMB_ENTRIES entries; 	/**< function entries */
	MDIS_PATH	path;		/**< path returned from M_open */
	SIGNAL		signal[NBR_OF_SIG];	/**< signal array */
}SMB_HANDLE;

/** Double linked List for alerts */
typedef struct
{
	UOS_DL_NODE n;							/**< list node */
	u_int16		addr;						/**< SMBus address */
	void		(*cbFunc)( void *cbArg );	/**< callback function */
	void		*cbArg;						/**< argument for callback function */
	u_int32		sigCode; 					/**< UOS_SIG signal code */
}ALERT_NODE;

/*-----------------------------------------+
|  GLOBALS                                 |
+-----------------------------------------*/
UOS_DL_LIST G_alertList;	/**< list for alert callbacks */

/*-----------------------------------------+
|  PROTOTYPES                              |
+-----------------------------------------*/
static void zeroOut( int8 *p, int32 size );
static int32 AlertRemove( void *smbHdl, ALERT_NODE *alertNode );
static ALERT_NODE* AlertFindByAddr( u_int16 addr );
static ALERT_NODE* AlertFindBySig( u_int32 sigCode );
static void __MAPILIB SigHandler(u_int32 sigCode);

/**
 * \defgroup _SMB2_API SMB2_API
 *  The SMB2_API provides access to the SMBus devices from user mode applications.
 *  @{
 */

/**********************************************************************/
/** Return ident string
 *
 *  \return 	ident string
 */
char* __MAPILIB SMB2API_Ident(	void )
{
    return( "SMB2_API: $Id: smb2_api.c,v 1.9 2010/04/19 13:42:16 dpfeuffer Exp $" );
}

/**********************************************************************/
/** Initialize library
 *
 *  The \a device will be opened and the SMB handle returned.
 *
 *  \param 	device	\IN  MDIS device name
 *  \param	smbHdlP	\INOUT pointer to variable for SMB handle
 *  \return 	0 on success or error code
 *
 *  \sa SMB2API_Exit
 */
int32 __MAPILIB SMB2API_Init( char *device, void **smbHdlP )
{
	MDIS_PATH	path;
	int32		size, ret;
	u_int32		si;
	SMB_HANDLE	*smbHdl=NULL;

	/* open device */
	if( (path = M_open(device)) < 0 )
		goto ERR_EXIT;

	/* alloc struct */
	size = sizeof(SMB_HANDLE);
	smbHdl = (SMB_HANDLE*)malloc( size );
	if( !smbHdl )
		goto ERR_EXIT;

	zeroOut( (int8*)smbHdl, size );

	/* fill jump table */
	smbHdl->entries.Exit				= SMB2API_Exit;
	smbHdl->entries.QuickComm			= SMB2API_QuickComm;
	smbHdl->entries.WriteByte			= SMB2API_WriteByte;
	smbHdl->entries.ReadByte			= SMB2API_ReadByte;
	smbHdl->entries.WriteByteData		= SMB2API_WriteByteData;
	smbHdl->entries.ReadByteData		= SMB2API_ReadByteData;
	smbHdl->entries.WriteWordData		= SMB2API_WriteWordData;
	smbHdl->entries.ReadWordData		= SMB2API_ReadWordData;
	smbHdl->entries.WriteBlockData		= SMB2API_WriteBlockData;
	smbHdl->entries.ReadBlockData		= SMB2API_ReadBlockData;
	smbHdl->entries.ProcessCall			= SMB2API_ProcessCall;
	smbHdl->entries.BlockProcessCall	= SMB2API_BlockProcessCall;
	smbHdl->entries.AlertResponse		= SMB2API_AlertResponse;
	smbHdl->entries.AlertCbInstall		= SMB2API_AlertCbInstall;
	smbHdl->entries.AlertCbRemove		= SMB2API_AlertCbRemove;
	smbHdl->entries.SmbXfer				= SMB2API_SmbXfer;
	smbHdl->entries.I2CXfer				= SMB2API_I2CXfer;

	/* fill private params */
	smbHdl->path = path;

	for( si=0; si<NBR_OF_SIG; si++ ){
		smbHdl->signal[si].sigCode = FIRST_SIG + si;
		smbHdl->signal[si].condition = SIG_FREE;
	}

	/* init list */
	UOS_DL_NewList( &G_alertList );

	/* retrun the handle */
	*smbHdlP = (void*)smbHdl;
	return 0;

/* error handling */
ERR_EXIT:
	ret = UOS_ErrnoGet();
	if( smbHdl )
		free( (void*)smbHdl );
	*smbHdlP = NULL;
	return ret;
}

/**********************************************************************/
/** Exit library
 *
 *  The open device will be closed and the SMB handle freed.
 *  *smbHdlP will be set to NULL.
 *
 *  \param	smbHdlP	\INOUT pointer to variable for SMB handle
 *  \return 	0 on success or error code
 *
 *  \sa SMB2API_Init
 */
int32 __MAPILIB SMB2API_Exit( void **smbHdlP )
{
	SMB_HANDLE *smbHdl = (SMB_HANDLE*)*smbHdlP;
	MDIS_PATH path = smbHdl->path;
	ALERT_NODE	*alertNode, *alertNodeNext;

	/* remove all installed alerts */
	alertNode = (ALERT_NODE*)G_alertList.head;
	alertNodeNext = (ALERT_NODE*)alertNode->n.next;
	while( alertNodeNext ){
		AlertRemove( smbHdl, alertNode );
		alertNodeNext = (ALERT_NODE*)alertNode->n.next;
	}

	free( (void*)smbHdl );
	*smbHdlP = NULL;

	/* close device */
	if( M_close( path ) < 0 )
		return UOS_ErrnoGet();

	return 0;
}

/****************************************************************************/
/** Quick command to a SMB device
 *
 *  The r/w bit of the address is the actual command issued to the device.
 *  This bit is set from the data parameter provided.
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     readWrite  \IN access to perform ( #SMB_READ or #SMB_WRITE )
 *
 *  \return    0 | error code
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_QuickComm(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		readWrite )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;
	trx.readWrite = readWrite;

	DO_BLK_SETSTAT( trx, SMB2_BLK_QUICK_COMM );

	return rv;
}

/****************************************************************************/
/** Write one data byte to a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     data		  \IN byte to write
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_ReadByte
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_WriteByte(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		data )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;
	trx.u.byteData = data;

	DO_BLK_SETSTAT( trx, SMB2_BLK_WRITE_BYTE );

	return rv;
}

/****************************************************************************/
/** Read one data byte from a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     dataP	  \OUT read byte
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_WriteByte
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_ReadByte(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		*dataP )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;

	DO_BLK_GETSTAT( trx, SMB2_BLK_READ_BYTE );
	if( rv )
		return rv;

	*dataP = trx.u.byteData;

	return rv;
}

/****************************************************************************/
/** Write command and one data byte to a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     cmdAddr	  \IN device command or index value
 *	\param     data		  \IN byte to write
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_ReadByteData
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_WriteByteData(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		cmdAddr,
	u_int8		data )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;
	trx.cmdAddr = cmdAddr;
	trx.u.byteData = data;

	DO_BLK_SETSTAT( trx, SMB2_BLK_WRITE_BYTE_DATA );

	return rv;
}

/****************************************************************************/
/** Write command and READ one data byte from a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     cmdAddr	  \IN device command or index value
 *	\param     dataP	  \OUT read byte
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_WriteByteData
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_ReadByteData(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		cmdAddr,
	u_int8		*dataP )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;
	trx.cmdAddr = cmdAddr;

	DO_BLK_GETSTAT( trx, SMB2_BLK_READ_BYTE_DATA );
	if( rv )
		return rv;

	*dataP = trx.u.byteData;

	return rv;
}

/****************************************************************************/
/** Write command and one data word to a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     cmdAddr	  \IN device command or index value
 *	\param     data		  \IN word to write
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_ReadWordData
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_WriteWordData(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		cmdAddr,
	u_int16		data )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;
	trx.cmdAddr = cmdAddr;
	trx.u.wordData = data;

	DO_BLK_SETSTAT( trx, SMB2_BLK_WRITE_WORD_DATA );

	return rv;
}

/****************************************************************************/
/** Write command and READ one data word from a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     cmdAddr	  \IN device command or index value
 *	\param     dataP	  \OUT read word
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_WriteWordData
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_ReadWordData(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		cmdAddr,
	u_int16		*dataP )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;
	trx.cmdAddr = cmdAddr;

	DO_BLK_GETSTAT( trx, SMB2_BLK_READ_WORD_DATA );
	if( rv )
		return rv;

	*dataP = trx.u.wordData;

	return rv;
}

/****************************************************************************/
/** Writes command and a data block to a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     cmdAddr	  \IN device command or index value
 *	\param     length	  \IN number of bytes to write
 *	\param     dataP	  \IN data block to write (1..32 bytes)
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_ReadBlockData
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_WriteBlockData(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		cmdAddr,
	u_int8		length,
	u_int8		*dataP )
{
	SMB2_TRANSFER_BLOCK trxBlk;
	int32 rv;

	/* check length */
	if( (length < 1) || (length > SMB_BLOCK_MAX_BYTES) )
		return (SMB_ERR_PARAM);

	zeroOut( (int8*)&trxBlk, sizeof(SMB2_TRANSFER_BLOCK) );
	trxBlk.flags = flags;
	trxBlk.addr = addr;
	trxBlk.cmdAddr = cmdAddr;
	trxBlk.u.length = length;
	memcpy( (void*)trxBlk.data, (void*)dataP, length );

	DO_BLK_SETSTAT( trxBlk, SMB2_BLK_WRITE_BLOCK_DATA );

	return rv;
}

/****************************************************************************/
/** Write command and READ one data block from a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     cmdAddr	  \IN device command or index value
 *	\param     lengthP	  \OUT number of bytes read
 *	\param     dataP	  \OUT read data block (1..32 bytes)
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_WriteBlockData
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_ReadBlockData(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		cmdAddr,
	u_int8		*lengthP,
	u_int8		*dataP )
{
	SMB2_TRANSFER_BLOCK trxBlk;
	int32 rv;

	zeroOut( (int8*)&trxBlk, sizeof(SMB2_TRANSFER_BLOCK) );
	trxBlk.flags = flags;
	trxBlk.addr = addr;
	trxBlk.cmdAddr = cmdAddr;

	*lengthP = 0;

	DO_BLK_GETSTAT( trxBlk, SMB2_BLK_READ_BLOCK_DATA );
	if( rv )
		return rv;

	*lengthP = trxBlk.u.length;
	memcpy( (void*)dataP, (void*)trxBlk.data, *lengthP );

	return rv;
}

/****************************************************************************/
/** Write command and one data word, then read one data word from a SMB device
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN device address
 *	\param     cmdAddr	  \IN device command or index value
 *	\param     dataP	  \INOUT word to write / read word
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_BlockProcessCall
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_ProcessCall(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		cmdAddr,
	u_int16		*dataP )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;
	trx.cmdAddr = cmdAddr;
	trx.u.wordData = *dataP;

	DO_BLK_GETSTAT( trx, SMB2_BLK_PROCESS_CALL );
	if( rv )
		return rv;

	*dataP = trx.u.wordData;

	return rv;
}

/****************************************************************************/
/** Write command and data block, then read data block from a SMB device
 *
 *  Note: \a writeLen + \a readLen must not exceed 32 bytes.
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl		\IN SMB handle
 *	\param     flags		\IN flags, see \ref _SMB2_FLAG
 *	\param     addr			\IN device address
 *	\param     cmdAddr		\IN device command or index value
 *	\param     writeLen		\IN number of bytes to write
 *	\param     *writeDataP	\IN data block to write (1..32 bytes)
 *  \param     *readLenP	\OUT number of bytes read
 *	\param     *readDataP   \OUT read data block (1..32 bytes)
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_ProcessCall
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_BlockProcessCall(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		cmdAddr,
	u_int8		writeLen,
	u_int8		*writeDataP,
	u_int8		*readLenP,
	u_int8		*readDataP )
{
	SMB2_TRANSFER_BLOCK trxBlk;
	int32 rv;

	/* check length */
	if( (writeLen < 1) || (writeLen > SMB_BLOCK_MAX_BYTES) )
		return (SMB_ERR_PARAM);

	zeroOut( (int8*)&trxBlk, sizeof(SMB2_TRANSFER_BLOCK) );
	trxBlk.flags = flags;
	trxBlk.addr = addr;
	trxBlk.cmdAddr = cmdAddr;
	trxBlk.u.writeLen = writeLen;
	memcpy( (void*)trxBlk.data, (void*)writeDataP, writeLen );

	*readLenP = 0;

	DO_BLK_GETSTAT( trxBlk, SMB2_BLK_READ_BLOCK_DATA );
	if( rv )
		return rv;

	*readLenP = trxBlk.readLen;
	memcpy( (void*)readDataP, (void*)(trxBlk.data + writeLen), *readLenP );

	return rv;
}

/****************************************************************************/
/** Read from / write to a SMB device using the SMBus protocol
 *
 *   Not supported by SMB2_API!
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl		\IN SMB handle
 *	\param     flags		\IN flags, see \ref _SMB2_FLAG
 *	\param     addr			\IN device address
 *	\param     readWrite	\IN access to perform ( #SMB_READ or #SMB_WRITE )
 *	\param     cmdAddr		\IN device command or index value
 *	\param     size			\IN size of data access (Quick/Byte/Word/Block/(Blk-)Proc
 *	\param     *dataP		\IN data to write / read data (1..32 bytes)
 *
 *  \return    0 | error code
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_SmbXfer(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int8		readWrite,
	u_int8		cmdAddr,
	u_int8		size,
	u_int8		*dataP )
{
	return -1;
}


/****************************************************************************/
/** Read from / write to a SMB device using the I2C protocol
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	\IN SMB handle
 *	\param     msg		\IN array of I2C messages (packets) to transfer
 *	\param     num      \IN number of messages in msg to transfer
 *
 *  \return    0 | error code
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_I2CXfer(
	void			*smbHdl,
	SMB_I2CMESSAGE	msg[],
	u_int32			num )
{
	int32	rv = 0;
	u_int32	n;

	for( n=0; n<num; n++ ){
		DO_BLK_GETSTAT( msg[n], SMB2_BLK_I2C_XFER );
		if( rv )
			return rv;
	}

	return rv;
}

/**********************************************************************/
/** Convert SMB2 and MDIS error code to string
 *
 * SMB2API_Errstring() creates an error message for error \a errCode and
 * returns a pointer to the generated string with the following
 * format:
 *
 * \verbatim
 * ERROR <errtype> <errcode>: <errdescr>
 * \endverbatim
 *
 * where \em errtype describes if the error code comes from the system
 * or the driver, \em errcode describes the error code in hexadecimal
 * format or in the operating system’s native format. \em errdescr is the
 * corresponding error message string.
 *
 * \b Examples:
 * \verbatim
    ERROR (MDIS) 0xE00E0f05: SMB2: Bus collision
    ERROR (MDIS) 0x1103: MK: illegal parameter
    ERROR (OS9) #000:221: module not found
   \endverbatim
 *
 *  \param errCode       \IN error code from SMB2 function
 *  \param strBuf        \OUT filled with error message (should have space
 *                           for 512 characters, including '\\0')
 *  \return				\a strBuf
 */
char* __MAPILIB SMB2API_Errstring(
	int32	errCode,
	char	*strBuf )
{
	u_int32		i;
    char		*smbErr = NULL;

	/* SMB2 error table */
	static struct _ERR_STR
	{
		int32  errCode;
		char*   errString;
	} errStrTable[] =
	{
		/* max string size indicator  |1---------------------------------------------50| */
		/* no error */
		{ SMB_ERR_NO				,"(no error)" },
		{ SMB_ERR_DESCRIPTOR		,"Initial data missing/wrong" },
		{ SMB_ERR_NO_MEM			,"Could not allocate ressources" },
		{ SMB_ERR_ADDR				,"Address not present or wrong" },
		{ SMB_ERR_BUSY				,"Bus is busy" },
		{ SMB_ERR_COLL				,"Bus collision" },
		{ SMB_ERR_NO_DEVICE			,"No device found" },
		{ SMB_ERR_PARAM				,"Wrong parameters passed" },
		{ SMB_ERR_PEC				,"PEC error detected" },
		{ SMB_ERR_NOT_SUPPORTED		,"Function/Access size not supported" },
		{ SMB_ERR_GENERAL			,"General Error (timeout, ...)" },
		{ SMB_ERR_ALERT_INSTALL		,"Alert callback installation failed" },
		{ SMB_ERR_ALERT_NOSIG		,"No free signal for alert" },
		{ SMB_ERR_ADDR_EXCLUDED		,"Address is excluded" },
		{ SMB_ERR_NO_IDLE			,"Bus did not get idle after STOP" },
		{ SMB_ERR_CTRL_BUSY			,"Controller is busy" },
		/* max string size indicator  |1---------------------------------------------50| */
	};

	#define NBR_OF_ERR sizeof(errStrTable)/sizeof(struct _ERR_STR)

	/*----------------------+
    |  SMB2 error?          |
    +----------------------*/
	if ( (errCode >= (ERR_DEV+0x80)) && (errCode < ERR_END) ) {

		/* search the error string */
		for(i = 0; i < NBR_OF_ERR; i++) {
			if ( errCode == (int32)errStrTable[i].errCode ) {
				smbErr	= errStrTable[i].errString;
			}
		}

		/* known SMB2 error */
		if (smbErr) {
			sprintf(strBuf, "ERROR (SMB2) 0x%04x: %s", errCode, smbErr);
		}
		/* unknown SMB2 error? */
		else {
			sprintf(strBuf, "ERROR (SMB2) 0x%04x: Unknown SMB2 error", errCode);
		}
	}
    /*----------------------+
    |  MDIS error?          |
    +----------------------*/
	else{
		M_errstringTs( errCode, strBuf );
	}

    return(strBuf);
}


/****************************************************************************/
/** Issue a read byte command to the Alert Response Address
 *
 *  If an alarm is returned by a device and the device address matches
 *  the address passed, \a alertCntP returns with an 1 set.
 *
 *  Furthermore the alert callback function (if any installed) will be called
 *  for any device address that returns an alert.
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     flags      \IN flags, see \ref _SMB2_FLAG
 *	\param     addr	      \IN 0x00 or device address to be compared with
 *	\param     alertCntP  \OUT number of received alerts
 *
 *  \return    0 | error code
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_AlertResponse(
	void		*smbHdl,
	u_int32		flags,
	u_int16		addr,
	u_int16		*alertCntP )
{
	SMB2_TRANSFER trx;
	int32 rv;

	zeroOut( (int8*)&trx, sizeof(SMB2_TRANSFER) );
	trx.flags = flags;
	trx.addr = addr;

	*alertCntP = 0;

	DO_BLK_GETSTAT( trx, SMB2_BLK_ALERT_RESPONSE );
	if( rv )
		return rv;

	*alertCntP = trx.u.alertCnt;

	return rv;
}

/****************************************************************************/
/** Install alert callback function
 *
 *  The alert callback function will be invoked if the specified SMBus device
 *  reports an alert.
 *
 *  The function requires a free UOS_SIG_USRx signal number and returns
 *  #SMB_ERR_ALERT_NOSIG if no one is available. In this case, the
 *  SMB2API_AlertCbInstallSig function should be used to specify an individual
 *  UOS library conform signal code.
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     addr		  \IN device address
 *	\param     cbFuncP	  \IN alert callback function to install
 *	\param     cbArgP	  \IN argument for alert callback function
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_AlertCbInstallSig
 *  \sa SMB2API_AlertCbRemove
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_AlertCbInstall(
	void		*smbHdl,
	u_int16		addr,
	void (*cbFuncP)( void *cbArg ),
	void		*cbArgP )
{
	u_int32		sigCode = 0, si;
	SMB_HANDLE	*h = (SMB_HANDLE*)smbHdl;

	/* get a free signal to use */
	for( si=0; si<NBR_OF_SIG; si++ ){
		if( h->signal[si].condition == SIG_FREE ){
			h->signal[si].condition = SIG_USED;
			sigCode = h->signal[si].sigCode;
			break;
		}
	}
	if( si == NBR_OF_SIG )
		return (SMB_ERR_ALERT_NOSIG);

	return SMB2API_AlertCbInstallSig( smbHdl, addr, cbFuncP, cbArgP, sigCode );
}

/****************************************************************************/
/** Install alert callback function
 *
 *  The alert callback function will be invoked if the specified SMBus device
 *  reports an alert.
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     addr		  \IN device address
 *	\param     cbFuncP	  \IN alert callback function to install
 *	\param     cbArgP	  \IN argument for alert callback function
 *	\param     sigCode	  \IN UOS library conform signal code
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_AlertCbInstall
 *  \sa SMB2API_AlertCbRemove
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_AlertCbInstallSig(
	void		*smbHdl,
	u_int16		addr,
	void (*cbFuncP)( void *cbArg ),
	void		*cbArgP,
	u_int32		sigCode )
{
	ALERT_NODE	*alertNode;
	SMB2_ALERT	alertCtrl;
	int32 rv;

	/* list empty (first alert)? */
	alertNode = (ALERT_NODE*)G_alertList.head;
	if( !alertNode->n.next ){

		/* install signal handler */
		if( UOS_SigInit(SigHandler) ){
			return (SMB_ERR_ALERT_INSTALL);
		}
	}

	/* install signal */
	if( (rv = UOS_SigInstall(sigCode)) ){
		printf("rv=0x%x\n", rv);
		if( !alertNode->n.next )
			UOS_SigExit();
		return (SMB_ERR_ALERT_INSTALL);
	}

	/* install alert callback */
	alertCtrl.addr = addr;
	alertCtrl.sigCode = sigCode;
	DO_BLK_SETSTAT( alertCtrl, SMB2_BLK_ALERT_CB_INSTALL );
	if( rv ){
		UOS_SigRemove( sigCode );
		if( !alertNode->n.next )
			UOS_SigExit();
		return rv;
	}

	/* create new alert node */
	if( !(alertNode = (ALERT_NODE*)malloc( sizeof(ALERT_NODE) )) ){
		DO_BLK_SETSTAT( alertCtrl, SMB2_BLK_ALERT_CB_REMOVE );
		UOS_SigRemove( sigCode );
		if( !alertNode->n.next )
			UOS_SigExit();
		return (SMB_ERR_NO_MEM);
	}

	/* init node */
	alertNode->addr = addr;
	alertNode->cbFunc = cbFuncP;
	alertNode->cbArg = cbArgP;
	alertNode->sigCode = sigCode;

	/* add node to the list */
	UOS_DL_AddTail( &G_alertList, &alertNode->n );

	return 0;
}

/****************************************************************************/
/** Remove alert callback function
 *
 *---------------------------------------------------------------------------
 *  \param     smbHdl	  \IN SMB handle
 *	\param     addr		  \IN device address
 *	\param     cbArgP	  \OUT argument for alert callback function
 *
 *  \return    0 | error code
 *
 *  \sa SMB2API_AlertCbInstall
 *  \sa SMB2API_AlertCbInstallSig
 *
 ****************************************************************************/
int32 __MAPILIB SMB2API_AlertCbRemove(
	void		*smbHdl,
	u_int16		addr,
	void		**cbArgP )
{
	ALERT_NODE	*alertNode;

	if( (alertNode = AlertFindByAddr( addr )) ){
		*cbArgP = alertNode->cbArg;
		return AlertRemove( smbHdl, alertNode );
	}

	/* alert node not found */
	return (SMB_ERR_PARAM);
}

/*! @} */

/* * * * * * * * * * * * * * * helper funtion * * * * * * * * * * * * * *
 *
 * Zero out data storage
 */
static void zeroOut( int8 *p, int32 size ){
	while( size-- )
		*p++ = 0;
}

/* * * * * * * * * * * * * * * helper funtion * * * * * * * * * * * * * *
 *
 * Remove specified alert node
 */
static int32 AlertRemove(
	void		*smbHdl,
	ALERT_NODE	*alertNode )
{
	SMB_HANDLE	*h = (SMB_HANDLE*)smbHdl;
	SMB2_ALERT	alertCtrl;
	int32		rv;
	u_int32		si;

	/* remove alert callback */
	alertCtrl.addr = alertNode->addr;
	alertCtrl.sigCode = alertNode->sigCode;
	DO_BLK_SETSTAT( alertCtrl, SMB2_BLK_ALERT_CB_REMOVE );
	if( rv )
		return rv;

	/* remove signal */
	if( UOS_SigRemove( alertNode->sigCode ) ){
		return (SMB_ERR_ALERT_INSTALL);
	}

	/* scan the list */
	for( si=0; si<NBR_OF_SIG; si++ ){
		/* signal from array? */
		if( h->signal[si].sigCode == alertNode->sigCode ){
			h->signal[si].condition = SIG_FREE;
			break;
		}
	}

	/* remove node from the list */
	UOS_DL_Remove( &alertNode->n );

	/* free the node */
	free( alertNode );

	/* list empty (last alert)? */
	alertNode = (ALERT_NODE*)G_alertList.head;
	if( !alertNode->n.next ){

		/* terminate signal handling */
		if( UOS_SigExit() ){
			return (SMB_ERR_ALERT_INSTALL);
		}
	}

	return 0;
}

/* * * * * * * * * * * * * * * helper funtion * * * * * * * * * * * * * *
 *
 * Return alert node for address or NULL if not found
 */
static ALERT_NODE* AlertFindByAddr( u_int16 addr )
{
	ALERT_NODE	*alertNode;

	/* scan the list */
	for( alertNode=(ALERT_NODE*)G_alertList.head;
         alertNode->n.next;
         alertNode = (ALERT_NODE*)alertNode->n.next ){

		/* alert node for specified addr? */
		if( alertNode->addr == addr )
			return alertNode;
	}

	/* alert node not found */
	return NULL;
}

/* * * * * * * * * * * * * * * helper funtion * * * * * * * * * * * * * *
 *
 * Return alert node for signal code or NULL if not found
 */
static ALERT_NODE* AlertFindBySig( u_int32 sigCode )
{
	ALERT_NODE	*alertNode;

	/* scan the list */
	for( alertNode=(ALERT_NODE*)G_alertList.head;
         alertNode->n.next;
         alertNode = (ALERT_NODE*)alertNode->n.next ){

		/* alert node for specified addr? */
		if( alertNode->sigCode == sigCode )
			return alertNode;
	}

	/* alert node not found */
	return NULL;
}

/* * * * * * * * * * * * * * * helper funtion * * * * * * * * * * * * * *
 *
 * Call alert callback function for signal code
 */
static void __MAPILIB SigHandler(u_int32 sigCode)
{
	ALERT_NODE	*alertNode;

	alertNode = AlertFindBySig( sigCode );

	if( alertNode ){
		alertNode->cbFunc( alertNode->cbArg );
	}
}




