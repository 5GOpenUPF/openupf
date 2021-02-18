# Q&A

The following questions are more concerned by users. If you have any other related questions, we may put them here

## Does openupf support high availability?
> Yes, but in the open source version, we haven't given the code related to high availability, but reserved the registration interface.

## Can the number of openupf units be expanded infinitely?
> No, LBU and SMU can be expanded to two (active and standby) in high availability mode, and FPU can be expanded to 256 at most

## Will openupf's highly available modules also be open source?
> Perhaps, there are other factors that determine that we can't open source

## How should we contribute
> You can contact us by email or send us your questions

## Can we develop high availability modules ourselves?
> Yes, but we have reserved our private callback registration interface. You may need more efforts to implement or replace it

## Can I dynamically adjust the configuration data while openupf is running?
> No, Most configuration parameters are static, especially some specification parameters (number of sessions, number of nodes, etc.),
> and some parameters can be modified through interactive command line (for example, up featrues)

