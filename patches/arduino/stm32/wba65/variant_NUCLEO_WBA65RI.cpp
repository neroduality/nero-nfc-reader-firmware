/*
 *******************************************************************************
 * Copyright (c) 2023, STMicroelectronics
 * All rights reserved.
 *
 * This software component is licensed by ST under BSD 3-Clause license,
 * the "License"; You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                        opensource.org/licenses/BSD-3-Clause
 *
 *******************************************************************************
 */
#if defined(ARDUINO_NUCLEO_WBA65RI)
#include "pins_arduino.h"

// Digital PinName array — NUCLEO-WBA65RI Arduino Uno V3 (UM3610 / Zephyr
// arduino_r3_connector.dtsi). Not the NUCLEO-WBA55CG map.
const PinName digitalPin[] = {
  PA_11,  // D0
  PA_12,  // D1
  PE_0,   // D2
  PB_13,  // D3
  PA_3,   // D4
  PB_14,  // D5
  PB_0,   // D6
  PD_14,  // D7 — X-NUCLEO-NFC08A1 LED106 / MCU_LED6 (UM3007)
  PA_10,  // D8
  PB_11,  // D9
  PB_9,   // D10 — shield CS / SPI2_NSS
  PC_3,   // D11 — SPI2_MOSI
  PA_9,   // D12 — SPI2_MISO
  PB_10,  // D13 — SPI2_SCK
  PB_1,   // D14
  PB_2,   // D15
  PA_4,   // A0 — shield IRQ (UM3007)
  PA_6,   // A1
  PA_2,   // A2
  PA_1,   // A3
  PA_5,   // A4
  PA_0,   // A5
  PD_8,   // LD1 (blue)
  PC_4,   // LD2 (green)
  PB_8,   // LD3 (red)
  PC_13,  // B1
  PC_5,   // B2
  PB_4,   // B3
  PB_12,  // VCP TX
  PA_8,   // VCP RX
  PC_15,  // OSC32_IN
  PC_14,  // OSC32_OUT
  PA_14,  // SWCLK
  PA_13,  // SWDIO
  PH_3    // BOOT0
};

// Analog (Ax) pin number array
const uint32_t analogInputPin[] = {
  16,  // A0, PA4
  17,  // A1, PA6
  18,  // A2, PA2
  19,  // A3, PA1
  20,  // A4, PA5
  21,  // A5, PA0
};

// ----------------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif

/**
  * @brief  System Clock Configuration
  * @param  None
  * @retval None
  */
WEAK void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {};
  RCC_PeriphCLKInitTypeDef PeriphClkInit = {};

  (void)HAL_PWREx_ConfigSupply(PWR_LDO_SUPPLY);

  /** Configure the main internal regulator output voltage
  */
  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK) {
    Error_Handler();
  }

  /** Configure LSE Drive Capability
  */
  HAL_PWR_EnableBkUpAccess();
  __HAL_RCC_LSEDRIVE_CONFIG(RCC_LSEDRIVE_MEDIUMLOW);

  /** Initializes the CPU, AHB and APB busses clocks — PLL matches TinyUSB BSP
   *  board_system_clock_config() in hw/bsp/stm32wba/boards/stm32wba_nucleo/board.h
   *  (64 MHz SYSCLK, 32 MHz AHB5/HSE path for USB PHY). ICACHE: hw_config_init(). */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI | RCC_OSCILLATORTYPE_HSE
                                     | RCC_OSCILLATORTYPE_LSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.HSEDiv = RCC_HSE_DIV1;
  RCC_OscInitStruct.LSEState = RCC_LSE_ON;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL1.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL1.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL1.PLLM = 2;
  RCC_OscInitStruct.PLL1.PLLN = 8;
  RCC_OscInitStruct.PLL1.PLLP = 2;
  RCC_OscInitStruct.PLL1.PLLQ = 2;
  RCC_OscInitStruct.PLL1.PLLR = 2;
  RCC_OscInitStruct.PLL1.PLLFractional = 0;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
    Error_Handler();
  }

  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                                | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2
                                | RCC_CLOCKTYPE_PCLK7 | RCC_CLOCKTYPE_HCLK5;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB7CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.AHB5_PLL1_CLKDivider = RCC_SYSCLK_PLL1_DIV2;
  RCC_ClkInitStruct.AHB5_HSEHSI_CLKDivider = RCC_SYSCLK_HSEHSI_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK) {
    Error_Handler();
  }
  /** Initializes the peripherals clock
  */
  PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART1 | RCC_PERIPHCLK_LPUART1;
  PeriphClkInit.Usart1ClockSelection = RCC_USART1CLKSOURCE_HSI;
  PeriphClkInit.Lpuart1ClockSelection = RCC_LPUART1CLKSOURCE_HSI;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK) {
    Error_Handler();
  }

  /* ICACHE is enabled by hw_config_init() after SystemClock_Config(); do not
   * configure it here — a second HAL_ICACHE_ConfigAssociativityMode() fails
   * and hw_config_init spins forever at 0x0800d7f8, so USB never starts. */
}

#ifdef __cplusplus
}
#endif
#endif /* ARDUINO_NUCLEO_WBA65RI* */
