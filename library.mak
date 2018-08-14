#***************************  M a k e f i l e  *******************************
#  
#         Author: dieter.pfeuffer@men.de
#          $Date: 2012/08/10 15:34:41 $
#      $Revision: 1.4 $
#                      
#    Description: Makefile descriptor file for SMB2_API lib
#                      
#---------------------------------[ History ]---------------------------------
#
#   $Log: library.mak,v $
#   Revision 1.4  2012/08/10 15:34:41  dpfeuffer
#   R: Windows compiler error: SMB2_API_COMPILE macro redefinition
#   M: undo of last modification
#
#   Revision 1.3  2012/04/23 13:54:46  ts
#   R: Windows SMB BBIS was changed
#   M: declare new switch SMB2_API_COMPATIBLE to keep previous functionality
#
#   Revision 1.2  2009/06/22 11:59:34  dpfeuffer
#   R: MDVE warning
#   M: added smb2.h
#
#   Revision 1.1  2006/02/28 15:57:46  DPfeuffer
#   Initial Revision
#
#-----------------------------------------------------------------------------
#   (c) Copyright 2006 by MEN mikro elektronik GmbH, Nuernberg, Germany 
#*****************************************************************************

MAK_NAME=smb2_api

MAK_INCL=$(MEN_INC_DIR)/men_typs.h    	\
		 $(MEN_INC_DIR)/mdis_err.h		\
         $(MEN_INC_DIR)/mdis_api.h		\
		 $(MEN_INC_DIR)/usr_oss.h		\
		 $(MEN_INC_DIR)/smb2_api.h		\
		 $(MEN_INC_DIR)/smb2_drv.h		\
		 $(MEN_INC_DIR)/smb2.h	\

MAK_INP1 = smb2_api$(INP_SUFFIX)

MAK_INP  = $(MAK_INP1)

