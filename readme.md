I'm trying to learn how to serialize and deserialize rust netlink messages with netlink-packet-core.
1) Extend the ping pong example to support NLAs as well.
2) Make a new tea and coffee example:
 - They will only have a single message called `Beverage` with a header `BvgGenMsg`.
     1) `BeverageMessage` will have two variants:`tea` or `coffee`.
     2) `BvgGenFamily` should be `hot` or `cold`.
   Flags could be:
     1) `NLM_F_SPILL` // We could spill our drink
     2) `NLM_F_SERVE` // We could serve our drink
     3) `NLM_F_DRINK` // We could drink our drink
     4) `NLM_F_WASH` // We could wash our hands with the drink
 - They will have attributes. Some examples of attributes could be:
     1) `CAFFENE_CONTENT(u32)`
     2) `HOTNESS(u32)`
     3) `PERSON_NAME(String)`

3) Create a conntrack message to list connections.
