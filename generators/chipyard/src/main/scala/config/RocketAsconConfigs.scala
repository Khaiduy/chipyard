package chipyard


import org.chipsalliance.cde.config.{Config}
import freechips.rocketchip.diplomacy.AsynchronousCrossing
import freechips.rocketchip.tile.{CharacterCountExample, OpcodeSet}

// --------------
// Rocket + Ascon Rocc Configs
// --

class RocketAsconConfigs extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++            // set RocketTiles to be 32-bit
  new freechips.rocketchip.subsystem.WithNSmallCores(1) ++
  new ascon.WithAsconRoccAccel ++
  new chipyard.config.AbstractConfig)

class RocketAsconBlackboxConfigs extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++            // set RocketTiles to be 32-bit
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++
    new ascon.WithAsconRoccAccelBlackbox ++
    new chipyard.config.AbstractConfig)

class RocketAsconCacheConfigs extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++            // set RocketTiles to be 32-bit
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++
    new ascon.WithAsconRoccAccelCache ++
    new chipyard.config.AbstractConfig)

class TinyRocket32Config extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++
  new chipyard.iobinders.WithDontTouchIOBinders(false) ++         // TODO FIX: Don't dontTouch the ports
  new freechips.rocketchip.subsystem.WithIncoherentBusTopology ++ // use incoherent bus topology
  new freechips.rocketchip.subsystem.WithNBanks(0) ++             // remove L2$
  new freechips.rocketchip.subsystem.WithNoMemPort ++             // remove backing memory
  new freechips.rocketchip.subsystem.With1TinyCore ++             // single tiny rocket-core
  new chipyard.config.AbstractConfig)

class RV32RocketMediumConfig extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++            // set RocketTiles to be 32-bit
  new freechips.rocketchip.subsystem.WithNMedCores(1) ++
  new chipyard.config.AbstractConfig)

class RV32RocketSmallConfig extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++            // set RocketTiles to be 32-bit
  new freechips.rocketchip.subsystem.WithNSmallCores(1) ++
  new sha3.WithSha3Printf ++
  new sha3.WithSha3Accel ++
  new chipyard.config.AbstractConfig)

