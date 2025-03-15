package com.kevinmcg.learnspringsecurity.service;

import java.time.Year;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

@SpringBootTest
public class DiscountServiceTest {

	@MockitoSpyBean
	private DiscountService discountService;
	
	@Test
	public void testCalculateDiscount_ValidPromoCode() {
		var discount = discountService.calculateDiscount(10, "THANKSGIVING");
		Assertions.assertEquals(1f, discount);
	}
	
	@Test
	public void testCalculateDiscount_ValidPromoCodeForYear2025() {
		Mockito.when(discountService.getCurrentYear()).thenReturn (Year.of(2025));
		var discount = discountService.calculateDiscount(10, "XMAS");
		Assertions.assertEquals(2.5f, discount);
	}
	
	@Test
	public void testCalculateDiscount_ValidPromoCodeForYear2026() {
		Mockito.when(discountService.getCurrentYear()).thenReturn (Year.of(2026));
		var discount = discountService.calculateDiscount(10, "XMAS");
		Assertions.assertEquals(0f, discount); // no discount for 2026
	}	
	
	@Test
	public void testCalculateDiscount_NullPromoCode() {
		Mockito.when(discountService.getCurrentYear()).thenReturn (Year.of(2026));
		var discount = discountService.calculateDiscount(10, null);
		Assertions.assertEquals(0f, discount); // no discount for null promo code
	}	
}
