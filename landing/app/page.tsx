import { Nav } from "@/components/Nav";
import { Hero } from "@/components/Hero";
import { Problem } from "@/components/Problem";
import { FeatureGrid } from "@/components/FeatureGrid";
import { HowItWorks } from "@/components/HowItWorks";
import { UseCases } from "@/components/UseCases";
import { Pricing } from "@/components/Pricing";
import { CTASection } from "@/components/CTASection";
import { Footer } from "@/components/Footer";

export default function HomePage() {
  return (
    <>
      <Nav/>
      <main>
        <Hero/>
        <Problem/>
        <FeatureGrid/>
        <HowItWorks/>
        <UseCases/>
        <Pricing/>
        <CTASection/>
      </main>
      <Footer/>
    </>
  );
}
