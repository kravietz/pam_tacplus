/* pam_tacplus.h
 * 
 * Copyright (C) 2010, Pawel Krawczyk <kravietz@ceti.pl> and
 * Jeroen Nijhof <jeroen@nijhofnet.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

/* pam_tacplus command line options */
#define PAM_TAC_DEBUG		0x01
#define PAM_TAC_ENCRYPT		0x02
#define PAM_TAC_FIRSTHIT	0x04
#define PAM_TAC_ACCT		0x08 /* account on all specified servers */

/* how many TACPLUS+ servers can be defined */
#define TAC_MAX_SERVERS		4

/* pam_tacplus major, minor and patchlevel version numbers */
#define PAM_TAC_VMAJ		1
#define PAM_TAC_VMIN		3
#define PAM_TAC_VPAT		3

#ifndef PAM_EXTERN
	#define PAM_EXTERN extern
#endif
