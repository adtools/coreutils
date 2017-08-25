/* Look up an environment variable, returning NULL in insecure situations.

   Copyright 2013-2017 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <config.h>

#include <stdlib.h>

#if defined __amigaos__ && defined __CLIB2__ /* AmigaOS using CLIB2 */
# define __USE_INLINE__ 1
# include <dos/dos.h>
# include <proto/dos.h>
# if defined __amigaos4__
#  include <dos/obsolete.h>
# endif
# define MAX_ENV_SIZE 1024  /* maximum number of environ entries */

char **environ = 0;

void ___makeenviron() __attribute__((constructor));
void ___freeenviron() __attribute__((destructor));

uint32
copy_env(struct Hook *hook, APTR userdata, struct ScanVarsMsg *message)
{
  static uint32 env_size = 1;  // environ is null terminated

  if ( strlen(message->sv_GDir) <= 4 )
  {
    if ( env_size == MAX_ENV_SIZE )
    {
      return 0;
    }

    ++env_size;

    char **env = (char **)hook->h_Data;
    uint32 size = strlen(message->sv_Name) + 1 + message->sv_VarLen + 1 + 1;
    char *buffer= (char*)malloc(size);

    snprintf(buffer, size-1, "%s=%s", message->sv_Name, message->sv_Var);

    *env = buffer;
    ++env;
    hook->h_Data = env;
  }

  return 0;
}

void
___makeenviron()
{
  size_t environ_size = MAX_ENV_SIZE * sizeof(char*);
  environ = (char **)malloc(environ_size);
  if ( !environ )
  {
    return;
  }

  memset(environ, 0, environ_size);

  struct Hook hook;
  memset(&hook, 0, sizeof(struct Hook));
  hook.h_Entry = copy_env;
  hook.h_Data = environ;

  ScanVars(&hook, GVF_LOCAL_ONLY, 0);
}

void
___freeenviron()
{
  for ( char **i = environ; *i != NULL; ++i )
  {
    free(*i);
    *i = 0;
  }

  free(environ);
  environ = 0;
}
#endif

#if !HAVE___SECURE_GETENV
# if HAVE_ISSETUGID || (HAVE_GETUID && HAVE_GETEUID && HAVE_GETGID && HAVE_GETEGID)
#  include <unistd.h>
# endif
#endif

char *
secure_getenv (char const *name)
{
#if HAVE___SECURE_GETENV /* glibc */
  return __secure_getenv (name);
#elif HAVE_ISSETUGID /* OS X, FreeBSD, NetBSD, OpenBSD */
  if (issetugid ())
    return NULL;
  return getenv (name);
#elif HAVE_GETUID && HAVE_GETEUID && HAVE_GETGID && HAVE_GETEGID /* other Unix */
  if (geteuid () != getuid () || getegid () != getgid ())
    return NULL;
  return getenv (name);
#elif (defined _WIN32 || defined __WIN32__) && ! defined __CYGWIN__ /* native Windows */
  /* On native Windows, there is no such concept as setuid or setgid binaries.
     - Programs launched as system services have high privileges, but they don't
       inherit environment variables from a user.
     - Programs launched by a user with "Run as Administrator" have high
       privileges and use the environment variables, but the user has been asked
       whether he agrees.
     - Programs launched by a user without "Run as Administrator" cannot gain
       high privileges, therefore there is no risk. */
  return getenv (name);
#else
  return NULL;
#endif
}
