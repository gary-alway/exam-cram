# AWS Certified Generative AI Developer - Professional

[Exam Guide](https://aws.amazon.com/certification/certified-generative-ai-developer-professional/)

---

Comprehend — NLP on text (entities, sentiment, topics)
Transcribe — speech → text
Translate — language → language
Polly — text → speech
Rekognition — image/video analysis
Textract — documents → structured data
Lex — chatbots / voice bots
Kendra — enterprise document search
Personalize — recommendations
Forecast — time-series prediction
Bedrock — foundation models / LLM access
SageMaker — build/train/deploy ML
HealthLake — healthcare data store + search
Fraud Detector — fraud prediction

Vector search indexes (for RAG / embeddings)
- IVF = Inverted File Index
- HNSW = Hierarchical Navigable Small World

|            | IVF          | HNSW        |
|------------|--------------|-------------|
| Approach   | Partition    | Graph-based |
| Memory     | Lower        | Higher      |
| Build time | Faster       | Slower      |
| Accuracy   | Lower        | Higher      |
| Query speed| Slower       | Faster      |

LLM inference parameters
- Temperature = randomness (0 = deterministic, 1 = creative)
- Top_p = nucleus sampling, probability threshold for tokens
- Top_k = number of token options to sample from
- Use Top_p OR Temperature, not both

A/B testing for model changes
- Bedrock Evaluations = evaluate model outputs
- CloudWatch Evidently = A/B testing + feature flags