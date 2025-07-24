// See LICENSE for license details.
package usb.fpga.arty100t

import sys.process._

import org.chipsalliance.cde.config._
import freechips.rocketchip.subsystem._
import freechips.rocketchip.devices.debug._
import freechips.rocketchip.devices.tilelink._
import org.chipsalliance.diplomacy._
import org.chipsalliance.diplomacy.lazymodule._
import freechips.rocketchip.system._
import freechips.rocketchip.tile._
import freechips.rocketchip.util.{SystemFileName}

import sifive.blocks.devices.uart._
import sifive.fpgashells.shell.{DesignKey}

import testchipip.serdes.{SerialTLKey}
import freechips.rocketchip.resources.{DTSModel, DTSTimebase}
import sifive.blocks.devices.spi.{PeripherySPIKey, SPIParams}
import sifive.blocks.devices.uart.{PeripheryUARTKey, UARTParams}
import sifive.fpgashells.shell.xilinx.{ArtyDDRSize}


import chipyard.{BuildSystem, ExtTLMem}
import chipyard.harness._

// don't use FPGAShell's DesignKey
class WithNoDesignKey extends Config((site, here, up) => {
  case DesignKey => (p: Parameters) => new SimpleLazyRawModule()(p)
})

class WithSystemModifications extends Config((site, here, up) => {
  case DTSTimebase => BigInt{(1e6).toLong}
  case BootROMLocated(x) => up(BootROMLocated(x), site).map { p =>
    // invoke makefile for sdboot
    val freqMHz = (site(SystemBusKey).dtsFrequency.get / (1000 * 1000)).toLong
    val make = s"make -C usb/src/main/resources/arty100t/sdboot PBUS_CLK=${freqMHz} bin"
    require (make.! == 0, "Failed to build bootrom")
    p.copy(hang = 0x10000, contentFileName = SystemFileName(s"./usb/src/main/resources/arty100t/sdboot/build/sdboot.bin"))
  }
  case ExtMem => up(ExtMem, site).map(x => x.copy(master = x.master.copy(size = site(ArtyDDRSize)))) // set extmem to DDR size (note the size)
  case SerialTLKey => Nil // remove serialized tl port
})

class WithDefaultPeripherals extends Config((site, here, up) => {
  case PeripheryUARTKey => List(UARTParams(address = BigInt(0x64000000L)))
  // case PeripheryUARTKey => List(UARTParams(address = BigInt(0x64020000L)))
  case PeripherySPIKey => List(SPIParams(rAddress = BigInt(0x64001000L)))
  // case PeripherySPIKey => List(SPIParams(rAddress = BigInt(0x64003000L)))
})

// By default, this uses the on-board USB-UART for the TSI-over-UART link
// The PMODUART HarnessBinder maps the actual UART device to JD pin
class WithArty100TTweaks(freqMHz: Double = 50) extends Config(
  new WithArty100TPMODUART ++
  new WithArty100TUARTTSI ++
  new WithArty100TDDRTL ++
  new WithArty100TJTAG ++
  new WithNoDesignKey ++
  new testchipip.tsi.WithUARTTSIClient ++
  new chipyard.harness.WithSerialTLTiedOff ++
  new chipyard.harness.WithHarnessBinderClockFreqMHz(freqMHz) ++
  new chipyard.config.WithUniformBusFrequencies(freqMHz) ++
  new chipyard.harness.WithAllClocksFromHarnessClockInstantiator ++
  new chipyard.clocking.WithPassthroughClockGenerator ++
  new chipyard.config.WithTLBackingMemory ++ // FPGA-shells converts the AXI to TL for us
  new freechips.rocketchip.subsystem.WithExtMemSize(BigInt(256) << 20) ++ // 256mb on ARTY
  new freechips.rocketchip.subsystem.WithoutTLMonitors)

class WithArty100TUSBTweaks(freqMHz: Double = 50) extends Config(
  //Clock
  new chipyard.harness.WithHarnessBinderClockFreqMHz(freqMHz) ++
  new chipyard.config.WithUniformBusFrequencies(freqMHz) ++
  new chipyard.harness.WithAllClocksFromHarnessClockInstantiator ++
  new chipyard.clocking.WithPassthroughClockGenerator ++

  //Peripherals
  new WithArty100TUART ++
  new WithArty100TSPISDCardHarnessBinder ++
  new WithDefaultPeripherals ++
  new chipyard.usb.mkv.WithMKV(address = BigInt(0x7000000L)) ++ // add MKV peripherals
  new WithArty100TJTAG ++
  new WithNoDesignKey ++

  //Others
  new WithArty100TDDRTL ++
  new WithSystemModifications ++ // setup busses, use sdboot bootrom, setup ext. mem. size
  new chipyard.config.WithTLBackingMemory ++ // FPGA-shells converts the AXI to TL for us
  new freechips.rocketchip.subsystem.WithoutTLMonitors
)

class RocketArty100TUSBConfig extends Config(
  new WithArty100TUSBTweaks ++
  new chipyard.config.WithBroadcastManager ++ // no l2
  new freechips.rocketchip.rocket.WithNRV32Cores(1) ++  // single rocket-core
  new chipyard.config.AbstractConfig)

class RocketArty100TConfig extends Config(
  new WithArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++ // no l2
  new chipyard.RocketConfig)

class NoCoresArty100TConfig extends Config(
  new WithArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++ // no l2
  new chipyard.NoCoresConfig)

// This will fail to close timing above 50 MHz
class BringupArty100TConfig extends Config(
  new WithArty100TSerialTLToGPIO ++
  new WithArty100TTweaks(freqMHz = 50) ++
  new testchipip.serdes.WithSerialTLPHYParams(testchipip.serdes.DecoupledInternalSyncSerialPhyParams(freqMHz=50)) ++
  new chipyard.ChipBringupHostConfig)



