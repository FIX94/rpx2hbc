#include <coreinit/core.h>
#include <coreinit/foreground.h>
#include <proc_ui/procui.h>
#include <sysapp/launch.h>
#include "common/common.h"
#include "kernel/gx2sploit.h"


bool isAppRunning = true;

void
SaveCallback()
{
   OSSavesDone_ReadyToRelease(); // Required
}

bool
AppRunning()
{
   if(!OSIsMainCore())
   {
      ProcUISubProcessMessages(true);
   }
   else
   {
      ProcUIStatus status = ProcUIProcessMessages(true);
    
      if(status == PROCUI_STATUS_EXITING)
      {
          // Being closed, deinit, free, and prepare to exit
          isAppRunning = false;
          ProcUIShutdown();
      }
      else if(status == PROCUI_STATUS_RELEASE_FOREGROUND)
      {
          // Free up MEM1 to next foreground app, deinit screen, etc.
          ProcUIDrawDoneRelease();
      }
      else if(status == PROCUI_STATUS_IN_FOREGROUND)
      {
         // Executed while app is in foreground
      }
   }

   return isAppRunning;
}

/* Entry point */
extern "C" int Menu_Main(void)
{
    //! *******************************************************************
    //! *    Check if our application needs to run the kexploit started   *
    //! *******************************************************************
    if(CheckKernelExploit() == 0)
    {
        return 0;
    }

   ProcUIInit(&SaveCallback);

   // Sends messages for ProcUI to release foreground, exit
   // and launch into the system menu immediately.
   SYSLaunchMenu();
   
   while(AppRunning());
   return 0;
}

