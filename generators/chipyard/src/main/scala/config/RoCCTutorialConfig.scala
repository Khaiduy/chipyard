package chipyard

import org.chipsalliance.cde.config.{Config}

class Tutorial1RocketConfig extends Config(
  new tut_1.WithTut01RoccAccel ++
  //new freechips.rocketchip.subsystem.WithRV32 ++
  new freechips.rocketchip.subsystem.WithNSmallCores(1) ++         // single rocket-core
  new chipyard.config.AbstractConfig)

class Tutorial1RocketConfigRV32 extends Config(
  new tut_1.WithTut01RoccAccel ++
  new freechips.rocketchip.subsystem.WithRV32 ++
  new freechips.rocketchip.subsystem.WithNSmallCores(1) ++         // single rocket-core
  new chipyard.config.AbstractConfig)
