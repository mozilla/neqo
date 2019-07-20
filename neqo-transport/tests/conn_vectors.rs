// Tests with the test vectors from the spec.
#![deny(warnings)]
use neqo_common::{Datagram, Encoder};
use neqo_transport::State;
use test_fixture::*;

const INITIAL_PACKET: &str = "c2ff000016088394c8f03e5157080000449e9bd3\
                              43fd65f354ebb400418b614f73765009c0162d59\
                              4777f9e6ddeb32fba3865cffd7e26e3724d4997c\
                              dde8df34f8868772fed2412d43046f44dc7c6adf\
                              5ee10da456d56c892c8f69594594e8dcabedb10d\
                              591130ca464588f2834eab931b10feb963c1947a\
                              05f57062692c242248ad0133b31f6dcc585ba344\
                              ca5beb382fb619272e65dfccae59c08eb00b7d2a\
                              5bbccd888582df1d1aee040aea76ab4dfdcae126\
                              791e71561b1f58312edb31c164ff1341fd2820e2\
                              399946bad901e425dae58a9859ef1825e7d757a6\
                              291d9ba6ee1a8c836dc0027cd705bd2bc67f56ba\
                              d0024efaa3819cbb5d46cefdb7e0df3ad92b0689\
                              650e2b49ac29e6398bedc755541a3f3865bc4759\
                              bec74d721a28a0452c1260189e8e92f844c91b27\
                              a00fc5ed6d14d8fceb5a848bea0a3208162c7a95\
                              782fcf9a045b20b76710a2565372f2541181030e\
                              4350e199e62fa4e2e0bba19ff66662ab8cc6815e\
                              eaa20b80d5f31c41e551f558d2c836a215ccff4e\
                              8afd2fec4bfcb9ea9d051d12162f1b14842489b6\
                              9d72a307d9144fced64fc4aa21ebd310f897cf00\
                              062e90dad5dbf04186622e6c1296d388176585fd\
                              b395358ecfec4d95db4429f4473a76210866fd18\
                              0eaeb60da433500c74c00aef24d77eae81755faa\
                              03e71a8879937b32d31be2ba51d41b5d7a1fbb4d\
                              952b10dd2d6ec171a3187cf3f64d520afad796e4\
                              188bc32d153241c083f225b6e6b845ce9911bd3f\
                              e1eb4737b71c8d55e3962871b73657b1e2cce368\
                              c7400658d47cfd9290ed16cdc2a6e3e7dcea77fb\
                              5c6459303a32d58f62969d8f4670ce27f591c7a5\
                              9cc3e7556eda4c58a32e9f53fd7f9d60a9c05cd6\
                              238c71e3c82d2efabd3b5177670b8d595151d7eb\
                              44aa401fe3b5b87bdb88dffb2bfb6d1d0d8868a4\
                              1ba96265ca7a68d06fc0b74bccac55b038f8362b\
                              84d47f52744323d08b46bfec8c421f991e139493\
                              8a546a7482a17c72be109ea4b0c71abc7d9c0ac0\
                              960327754e1043f18a32b9fb402fc33fdcb6a0b4\
                              fdbbddbdf0d85779879e98ef211d104a5271f228\
                              23f16942cfa8ace68d0c9e5b52297da9702d8f1d\
                              e24bcd06284ac8aa1068fa21a82abbca7e7454b8\
                              48d7de8c3d43560541a362ff4f6be06c0115e3a7\
                              33bff44417da11ae668857bba2c53ba17db8c100\
                              f1b5c7c9ea960d3f3d3b9e77c16c31a222b498a7\
                              384e286b9b7c45167d5703de715f9b0670840356\
                              2dcff77fdf2793f94e294888cebe8da4ee88a53e\
                              38f2430addc161e8b2e2f2d40541d10cda9a7aa5\
                              18ac14d0195d8c20120b4f1d47d6d0909e69c4a0\
                              e641b83c1ad4fff85af4751035bc5698b6141ecc\
                              3fbffcf2f55036880071ba1189274007967f6446\
                              8172854d140d229320d689f57660f6c445e629d1\
                              5ff2dcdff4b71a41ec0c24bd2fd8f5ad13b2c368\
                              8e0fdb8dbcce42e6cf49cf60d022ccd5b19b4fd5\
                              d98dc10d9ce3a626851b1fdd23e1fa3a961f9b03\
                              33ab8d632e48c944b82bdd9e800fa2b2b9e31e96\
                              aee54b40edaf6b79ec211fdc95d95ef552aa5325\
                              83d76a539e988e416a0a10df2550cdeacafc3d61\
                              b0b0a79337960a0be8cf6169e4d55fa6e7a9c2e8\
                              efabab3da008f5bcc38c1bbabdb6c10368723da0\
                              ae83c4b1819ff54946e7806458d80d7be2c867d4\
                              6fe1f0290c22645746b8bb00b6cba4f5b82f9b24";

#[test]
fn process_client_initial() {
    let mut server = default_server();

    let pkt: Vec<u8> = Encoder::from_hex(INITIAL_PACKET).into();
    let dgram = Datagram::new(loopback(), loopback(), pkt);
    assert_eq!(*server.state(), State::WaitInitial);
    let (out, _) = server.process(vec![dgram], now());
    assert_eq!(*server.state(), State::Handshaking);
    assert_eq!(out.len(), 1);
}
