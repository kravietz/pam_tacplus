/* support.h - support functions for pam_tacplus.c
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

#ifndef __linux__
	#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

/* support.c */
extern int _pam_parse (int argc, const char **argv);
extern unsigned long _resolve_name (char *serv);
extern int tacacs_get_password (pam_handle_t * pamh, int flags
			,int ctrl, char **password);
extern int converse (pam_handle_t * pamh, int nargs
		,struct pam_message **message
		,struct pam_response **response);
extern void _pam_log (int err, const char *format,...);
extern void *_xcalloc (size_t size);
extern char *_pam_get_terminal(pam_handle_t *pamh);
