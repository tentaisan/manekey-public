ASSERT(_stack_end != 0x20000000 || _stack_start - _stack_end >= __mpu_min_stack, "RP2040 MPU privileged stack reserve too small");
ASSERT(__sidata + (__edata - __sdata) <= 0x10100000, "RP2040 MPU public image exceeds first MiB");
