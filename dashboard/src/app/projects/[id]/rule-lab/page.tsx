import { RuleFixtureWorkbench } from "@/components/rules/rule-fixture-workbench";

export default async function RuleLabPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <RuleFixtureWorkbench key={id} projectId={id} />;
}
